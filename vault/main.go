package main

import (
	"context"
	"crypto/tls"
	"fmt"
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

	"vault/api"
	"vault/db"
	"vault/macaroon"
	"vault/oauth2"
	"vault/pocketbase"
	"vault/sigv4"
	"vault/vault"
)

type domainCredential struct {
	authType     string
	headerName   string
	headerPrefix string

	// Static API key (for authType="static")
	apiKey string

	// OAuth2 config (for authType="oauth2")
	oauth2Config *oauth2.OAuth2Config

	// SigV4 config (for authType="sigv4")
	sigv4Config *sigv4.Config

	// PocketBase config (for authType="pocketbase")
	pocketbaseConfig *pocketbase.Config
}

type authServer struct {
	authv3.UnimplementedAuthorizationServer
	verifier *macaroon.Verifier
	// Map of host -> credential config
	credentials map[string]domainCredential
	// OAuth2 token manager for handling token refresh
	tokenManager *oauth2.TokenManager
	// PocketBase token manager for handling PB auth
	pbTokenManager *pocketbase.TokenManager
	// StrictMode requires macaroon tokens for all requests (no passthrough)
	strictMode bool
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

	// Detect macaroon token: either Bearer acm_xxx or SigV4 Credential=acm_xxx/...
	tokenPrefix := s.verifier.GetTokenPrefix()
	isBearerMacaroon := macaroon.IsMacaroonAuth(authHeader, tokenPrefix)
	sigv4Macaroon := sigv4.ExtractAccessKey(authHeader)
	isSigV4Macaroon := strings.HasPrefix(sigv4Macaroon, tokenPrefix)

	// Passthrough: unrecognized token format (unless strict mode)
	if !isBearerMacaroon && !isSigV4Macaroon {
		if s.strictMode {
			log.Printf("Strict mode: rejected non-macaroon request to %s %s", host, access.Path)
			return &authv3.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied)},
				HttpResponse: &authv3.CheckResponse_DeniedResponse{
					DeniedResponse: &authv3.DeniedHttpResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_Unauthorized},
						Body:   "Unauthorized: macaroon token required",
					},
				},
			}, nil
		}
		log.Printf("Passthrough: %s %s %s", access.Method, host, access.Path)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK)},
		}, nil
	}

	// Normalize auth header for macaroon verification
	// For SigV4: extract the macaroon from Credential field and wrap as Bearer
	verifyAuth := authHeader
	if isSigV4Macaroon {
		verifyAuth = "Bearer " + sigv4Macaroon
	}

	// Macaroon token: validate and inject credentials
	result := s.verifier.VerifyRequest(verifyAuth, access)
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

	// Validate upstream restrictions (methods/paths from envoy context_extensions)
	contextExtensions := req.GetAttributes().GetContextExtensions()
	if allowedMethods, ok := contextExtensions["allowed_methods"]; ok && allowedMethods != "" {
		method := strings.ToUpper(httpReq.GetMethod())
		allowed := false
		for _, m := range strings.Split(allowedMethods, ",") {
			if strings.ToUpper(strings.TrimSpace(m)) == method {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("Upstream restriction: method %s not allowed for %s (allowed: %s)", method, host, allowedMethods)
			return &authv3.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied)},
				HttpResponse: &authv3.CheckResponse_DeniedResponse{
					DeniedResponse: &authv3.DeniedHttpResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
						Body:   fmt.Sprintf("Method %s not allowed for %s (allowed: %s)", method, host, allowedMethods),
					},
				},
			}, nil
		}
	}
	if allowedPaths, ok := contextExtensions["allowed_paths"]; ok && allowedPaths != "" {
		reqPath := httpReq.GetPath()
		// Strip query string for matching
		if idx := strings.IndexByte(reqPath, '?'); idx >= 0 {
			reqPath = reqPath[:idx]
		}
		matched := false
		patterns := strings.Split(allowedPaths, ",")
		for _, pattern := range patterns {
			if macaroon.MatchPath(strings.TrimSpace(pattern), reqPath) {
				matched = true
				break
			}
		}
		if !matched {
			log.Printf("Upstream restriction: path %s not allowed for %s (allowed: %s)", httpReq.GetPath(), host, allowedPaths)
			return &authv3.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied)},
				HttpResponse: &authv3.CheckResponse_DeniedResponse{
					DeniedResponse: &authv3.DeniedHttpResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
						Body:   fmt.Sprintf("Path %s not allowed for %s (allowed: %s)", httpReq.GetPath(), host, allowedPaths),
					},
				},
			}, nil
		}
	}

	// Look up credential config for this host
	cred, ok := s.credentials[host]
	if !ok {
		log.Printf("Auth failed: no credentials configured for %s", host)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Body:   "No credentials configured for this host",
				},
			},
		}, nil
	}

	// Resolve credential headers based on type
	respHeaders, err := s.resolveCredentialHeaders(cred, host, httpReq)
	if err != nil {
		log.Printf("Credential resolution failed for %s: %v", host, err)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.Internal)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_InternalServerError},
					Body:   "Failed to resolve credentials",
				},
			},
		}, nil
	}

	log.Printf("Auth successful for %s %s %s", access.Method, host, access.Path)
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: respHeaders,
			},
		},
	}, nil
}

// resolveCredentialHeaders returns the headers to inject based on credential type
func (s *authServer) resolveCredentialHeaders(cred domainCredential, host string, httpReq interface{ GetMethod() string; GetPath() string; GetHeaders() map[string]string }) ([]*corev3.HeaderValueOption, error) {
	switch cred.authType {
	case "static":
		return []*corev3.HeaderValueOption{{
			Header: &corev3.HeaderValue{
				Key:   cred.headerName,
				Value: cred.headerPrefix + cred.apiKey,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}, nil

	case "oauth2":
		token, err := s.tokenManager.GetAccessToken(host, cred.oauth2Config)
		if err != nil {
			return nil, fmt.Errorf("oauth2 token refresh: %w", err)
		}
		return []*corev3.HeaderValueOption{{
			Header: &corev3.HeaderValue{
				Key:   cred.headerName,
				Value: cred.headerPrefix + token,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}, nil

	case "sigv4":
		cfg := cred.sigv4Config
		headers := httpReq.GetHeaders()
		signed, err := sigv4.SignRequest(
			cfg,
			httpReq.GetMethod(),
			host,
			httpReq.GetPath(),
			headers,
		)
		if err != nil {
			return nil, fmt.Errorf("sigv4 signing: %w", err)
		}
		var result []*corev3.HeaderValueOption
		for k, v := range signed {
			result = append(result, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   k,
					Value: v,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
		return result, nil

	case "pocketbase":
		token, err := s.pbTokenManager.GetToken(host, cred.pocketbaseConfig)
		if err != nil {
			return nil, fmt.Errorf("pocketbase auth: %w", err)
		}
		return []*corev3.HeaderValueOption{{
			Header: &corev3.HeaderValue{
				Key:   cred.headerName,
				Value: token,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}}, nil

	default:
		return nil, fmt.Errorf("unknown auth type: %s", cred.authType)
	}
}

func main() {
	// Load vault config (vault.yaml preferred, env vars as fallback)
	vaultPath := os.Getenv("VAULT_CONFIG")
	if vaultPath == "" {
		vaultPath = "vault.yaml"
	}

	vaultCfg, err := vault.Load(vaultPath)
	if err != nil {
		// Fallback: construct config from env vars for backward compatibility
		log.Printf("No vault.yaml found, falling back to env vars")
		vaultCfg = &vault.Config{
			SigningKey:    os.Getenv("MACAROON_SIGNING_KEY"),
			EncryptionKey: os.Getenv("MACAROON_ENCRYPTION_KEY"),
			Credentials:  make(map[string]vault.CredentialConfig),
		}
	}

	// Load macaroon keys: from config, or fall back to env vars
	var keyStore *macaroon.KeyStore
	if vaultCfg.SigningKey != "" {
		keyStore, err = macaroon.LoadKeyStoreFromConfig(vaultCfg.SigningKey, vaultCfg.EncryptionKey)
		if err != nil {
			log.Fatalf("Failed to load macaroon keys from config: %v", err)
		}
	} else {
		keyStore, err = macaroon.LoadKeyStore()
		if err != nil {
			log.Fatalf("Failed to load macaroon keys: %v", err)
		}
	}
	log.Printf("Loaded macaroon signing key")

	warnings, err := vaultCfg.Validate()
	if err != nil {
		// Validation failure is non-fatal when using env var fallback
		log.Printf("Warning: vault config validation: %v", err)
	}
	for _, w := range warnings {
		log.Printf("Warning: %s", w)
	}

	verifier := macaroon.NewVerifier(keyStore)
	tokenManager := oauth2.NewTokenManager()
	pbTokenManager := pocketbase.NewTokenManager()

	// Resolve credentials
	credentials := make(map[string]domainCredential)

	resolved, err := vaultCfg.Resolve()
	if err != nil {
		log.Printf("Warning: failed to resolve credentials: %v", err)
	}
	for host, cred := range resolved {
		dc := domainCredential{
			headerName: cred.HeaderName,
		}
		switch cred.Type {
		case "sigv4":
			dc.authType = "sigv4"
			dc.sigv4Config = &sigv4.Config{
				Region:         cred.SigV4Config.Region,
				Service:        cred.SigV4Config.Service,
				AccessKeyID:    cred.SigV4Config.AccessKeyID,
				SecretAccessKey: cred.SigV4Config.SecretAccessKey,
			}
		case "pocketbase":
			dc.authType = "pocketbase"
			dc.pocketbaseConfig = &pocketbase.Config{
				URL:        cred.PocketBaseConfig.URL,
				Collection: cred.PocketBaseConfig.Collection,
				Email:      cred.PocketBaseConfig.Email,
				Password:   cred.PocketBaseConfig.Password,
			}
		default:
			dc.authType = "static"
			dc.apiKey = cred.Value
		}
		credentials[host] = dc
		log.Printf("Loaded %s credentials for %s", cred.Type, host)
	}

	if len(credentials) == 0 {
		log.Printf("Warning: No credentials configured in %s", vaultPath)
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
		httpPort = "8033"
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

	// STRICT_MODE: require macaroon tokens (no passthrough)
	strictMode := os.Getenv("STRICT_MODE") == "true" || os.Getenv("STRICT_MODE") == "1"
	if strictMode {
		log.Printf("Strict mode enabled: all requests require macaroon tokens")
	}
	log.Printf("Token prefix: %s", macaroon.TokenPrefix)

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, &authServer{
		verifier:       verifier,
		credentials:    credentials,
		tokenManager:   tokenManager,
		pbTokenManager: pbTokenManager,
		strictMode:     strictMode,
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

	log.Printf("gRPC vault server listening on %s", grpcPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// Silence unused import warning
var _ = tls.Config{}
