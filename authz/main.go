package main

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"authz/macaroon"
)

type authServer struct {
	authv3.UnimplementedAuthorizationServer
	verifier *macaroon.Verifier
	// Map of host -> API key
	apiKeys map[string]string
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

	// Verify macaroon token
	authHeader := headers["authorization"]
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

	// Look up API key for this host
	apiKey, ok := s.apiKeys[host]
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

	log.Printf("Auth successful for %s %s %s", access.Method, host, access.Path)
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{{
					Header: &corev3.HeaderValue{
						Key:   "authorization",
						Value: "Bearer " + apiKey,
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

	// hostEnvMap is defined in domains_gen.go (generated from domains.toml)
	apiKeys := make(map[string]string)
	for host, envVar := range hostEnvMap {
		if key := os.Getenv(envVar); key != "" {
			apiKeys[host] = key
			log.Printf("Loaded API key for %s", host)
		}
	}

	if len(apiKeys) == 0 {
		log.Fatal("No API keys configured. Set STRIPE_API_KEY, OPENAI_API_KEY, etc.")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9001"
	}
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	server := grpc.NewServer()
	authv3.RegisterAuthorizationServer(server, &authServer{
		verifier: verifier,
		apiKeys:  apiKeys,
	})

	log.Printf("Authz server listening on %s", port)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
