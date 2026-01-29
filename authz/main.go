package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"authz/api"
	"authz/db"
	"authz/macaroon"
	"authz/oauth2"
	"authz/vault"
)

type domainCredential struct {
	// Static API key (for auth_type="static")
	apiKey       string
	headerName   string
	headerPrefix string

	// OAuth2 config (for auth_type="oauth2")
	authType     string
	oauth2Config *oauth2.OAuth2Config
}

type authServer struct {
	authv3.UnimplementedAuthorizationServer
	verifier *macaroon.Verifier
	// Map of host -> credential config
	credentials map[string]domainCredential
	// OAuth2 token manager for handling token refresh
	tokenManager *oauth2.TokenManager
}

func (s *authServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpReq.GetHeaders()

	// Get target host from x-target-host header (flycast rewrites Host)
	host := headers["x-target-host"]
	if host == "" {
		host = headers["host"]
	}
	if host == "" {
		host = headers[":authority"]
	}

	// Build Access from request
	access := &macaroon.Access{
		Host:      host,
		Method:    httpReq.GetMethod(),
		Path:      httpReq.GetPath(),
		Timestamp: time.Now(),
	}

	// Check for authorization header
	authHeader := headers["authorization"]

	// No auth header = pass through without credential injection
	if authHeader == "" {
		log.Printf("No auth header, passing through: %s %s", access.Method, access.Path)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK)},
		}, nil
	}

	// Verify macaroon token
	result := s.verifier.VerifyRequest(authHeader, access)

	if !result.Valid {
		log.Printf("Auth failed: %s", result.Error)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Unauthorized},
					Body:   "Unauthorized: " + result.Error,
				},
			},
		}, nil
	}

	// Look up credential config for this host
	cred, ok := s.credentials[host]
	if !ok {
		log.Printf("Auth failed: unknown host %s", host)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Body:   "Unknown service",
				},
			},
		}, nil
	}

	// Get the API key/token to inject
	var apiToken string
	if cred.authType == "oauth2" {
		// OAuth2: get fresh access token
		token, err := s.tokenManager.GetAccessToken(host, cred.oauth2Config)
		if err != nil {
			log.Printf("OAuth2 token refresh failed for %s: %v", host, err)
			return &authv3.CheckResponse{
				Status: &status.Status{Code: int32(codes.Internal)},
				HttpResponse: &authv3.CheckResponse_DeniedResponse{
					DeniedResponse: &authv3.DeniedHttpResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_InternalServerError},
						Body:   "Failed to refresh OAuth2 token",
					},
				},
			}, nil
		}
		apiToken = token
	} else {
		// Static: use configured API key
		apiToken = cred.apiKey
	}

	log.Printf("Auth successful for %s %s %s", access.Method, host, access.Path)
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{{
					Header: &corev3.HeaderValue{
						Key:   cred.headerName,
						Value: cred.headerPrefix + apiToken,
					},
					AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
				}},
			},
		},
	}, nil
}

func main() {
	// Load macaroon keys
	keyStore, err := macaroon.LoadKeyStore()
	if err != nil {
		log.Fatalf("Failed to load macaroon keys: %v", err)
	}
	log.Printf("Loaded macaroon signing key")

	verifier := macaroon.NewVerifier(keyStore)
	tokenManager := oauth2.NewTokenManager()

	// Load credentials from vault.toml
	credentials := make(map[string]domainCredential)

	vaultPath := os.Getenv("VAULT_CONFIG")
	if vaultPath == "" {
		vaultPath = "vault.toml"
	}

	if vaultCfg, err := vault.Load(vaultPath); err != nil {
		log.Printf("Warning: Failed to load vault.toml: %v", err)
	} else {
		resolved, err := vaultCfg.Resolve()
		if err != nil {
			log.Printf("Warning: Failed to resolve vault credentials: %v", err)
		} else {
			for host, cred := range resolved {
				credentials[host] = domainCredential{
					apiKey:       cred.Value,
					headerName:   cred.HeaderName,
					headerPrefix: "", // Value already includes prefix
					authType:     "static",
				}
				log.Printf("Loaded %s credentials for %s", cred.Type, host)
			}
		}
	}

	if len(credentials) == 0 {
		log.Printf("Warning: No credentials configured. Create vault.toml or set VAULT_CONFIG.")
	}

	// Open database
	database, err := db.OpenDefault()
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()
	log.Printf("Database opened")

	// Cleanup expired sessions periodically
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := database.CleanupExpired(); err != nil {
				log.Printf("Cleanup error: %v", err)
			}
		}
	}()

	// Start HTTP API server
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}
	rpOrigin := os.Getenv("WEBAUTHN_RP_ORIGIN")
	if rpOrigin == "" {
		rpOrigin = "https://localhost:" + httpPort
	}
	rpName := os.Getenv("WEBAUTHN_RP_NAME")
	if rpName == "" {
		rpName = "Agent Credentials"
	}

	apiServer, err := api.NewServer(database, rpID, rpOrigin, rpName)
	if err != nil {
		log.Fatalf("Failed to create API server: %v", err)
	}

	httpServer := &http.Server{
		Addr:    ":" + httpPort,
		Handler: apiServer,
	}

	// Start HTTP server in goroutine
	go func() {
		// Check for TLS cert/key
		certFile := os.Getenv("TLS_CERT_FILE")
		keyFile := os.Getenv("TLS_KEY_FILE")

		if certFile != "" && keyFile != "" {
			log.Printf("HTTP API server listening on https://:%s", httpPort)
			if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		} else {
			log.Printf("HTTP API server listening on http://:%s", httpPort)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		}
	}()

	// Start gRPC server
	grpcPort := os.Getenv("PORT")
	if grpcPort == "" {
		grpcPort = "9001"
	}
	if !strings.HasPrefix(grpcPort, ":") {
		grpcPort = ":" + grpcPort
	}

	lis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, &authServer{
		verifier:     verifier,
		credentials:  credentials,
		tokenManager: tokenManager,
	})

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		grpcServer.GracefulStop()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	}()

	log.Printf("gRPC authz server listening on %s", grpcPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// Silence unused import warning
var _ = tls.Config{}
