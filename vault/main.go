package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
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
	"vault/policy"
	"vault/provider"
	"vault/provider/jsvm"
	"vault/sigv4"
	"vault/vault"
)

type configuredCredential struct {
	name           string
	credentialType string
	extractor      provider.CredentialExtractor
	provider       provider.CredentialProvider
	policy         string
}

type authServer struct {
	authv3.UnimplementedAuthorizationServer
	verifier *macaroon.Verifier
	// Map of configured credential key -> provider.
	credentials map[string]configuredCredential
	// Map of configured policy key -> trusted upstream authorizer.
	policies map[string]policy.Authorizer
	// StrictMode requires macaroon tokens for all requests (no passthrough)
	strictMode bool
	// Database for audit logging
	database *db.DB
}

func (s *authServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpReq.GetHeaders()
	contextExtensions := req.GetAttributes().GetContextExtensions()
	routeMode := contextExtensions["agent_creds_mode"]
	routePolicy := strings.TrimPrefix(contextExtensions["policy"], "/")

	// Prefer the original target host when an upstream proxy rewrites Host.
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

	// Envoy chooses the credential from trusted route metadata. That binding
	// is available to an optional credential-specific extractor before the
	// capability is verified; the extractor itself receives no secret config.
	credentialKey := host
	if configured := strings.TrimPrefix(contextExtensions["credential"], "/"); configured != "" {
		credentialKey = configured
	}
	cred, hasConfiguredCredential := s.credentials[credentialKey]

	// Let the selected credential adapter understand client-specific framing.
	// Built-in schemes remain the fallback for built-in providers and identity
	// routes. Go verifies every returned token before injection is possible.
	authHeader := headers["authorization"]
	tokenPrefix := s.verifier.GetTokenPrefix()
	var requestToken string
	if routeMode != "identity" && hasConfiguredCredential && cred.extractor != nil {
		var extractionErr error
		requestToken, extractionErr = cred.extractor.Extract(ctx, provider.ExtractionRequest{
			Credential:     credentialKey,
			CredentialType: cred.credentialType,
			Host:           host,
			Method:         httpReq.GetMethod(),
			Path:           httpReq.GetPath(),
			Headers:        headers,
		})
		if extractionErr != nil {
			reason := fmt.Sprintf("credential extraction failed: %v", extractionErr)
			log.Printf("%s for %s", reason, host)
			s.logAudit("deny", access.Method, host, access.Path, reason, nil)
			return credentialExtractionErrorResponse(), nil
		}
	}
	if requestToken == "" {
		requestToken, _ = extractBuiltinCapabilityToken(authHeader, tokenPrefix)
	}
	hasRequestToken := requestToken != ""

	// Identity routes and routes with an explicit policy are authentication
	// boundaries even when global strict mode is disabled. Never allow the
	// passthrough path to bypass them.
	requiresMacaroon := s.strictMode || routeMode == "identity" || routePolicy != ""

	// Passthrough: unrecognized token format (unless this route requires auth)
	if !hasRequestToken {
		if requiresMacaroon {
			log.Printf("Rejected non-macaroon request to protected route %s %s", host, access.Path)
			s.logAudit("deny", access.Method, host, access.Path, "macaroon token required", nil)
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

	// Extract token ID for audit logging
	rawToken := requestToken
	if idx := strings.IndexByte(rawToken, ','); idx >= 0 {
		rawToken = strings.TrimSpace(rawToken[:idx])
	}
	tokenID := extractTokenID(rawToken)

	// Macaroon token: validate and inject credentials
	result := s.verifier.VerifyRequest("Bearer "+requestToken, access)
	if !result.Valid {
		log.Printf("Auth failed: %s", result.Error)
		s.logAudit("deny", access.Method, host, access.Path, result.Error, tokenID)
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
			reason := fmt.Sprintf("method %s not allowed (allowed: %s)", method, allowedMethods)
			log.Printf("Upstream restriction: %s for %s", reason, host)
			s.logAudit("deny", access.Method, host, access.Path, reason, tokenID)
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
			reason := fmt.Sprintf("path %s not allowed (allowed: %s)", httpReq.GetPath(), allowedPaths)
			log.Printf("Upstream restriction: %s for %s", reason, host)
			s.logAudit("deny", access.Method, host, access.Path, reason, tokenID)
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

	mode := routeMode
	if mode == "identity" {
		if result.Subject == nil {
			reason := "identity route requires a subject-scoped token"
			s.logAudit("deny", access.Method, host, access.Path, reason, tokenID)
			return &authv3.CheckResponse{
				Status: &status.Status{Code: int32(codes.PermissionDenied)},
				HttpResponse: &authv3.CheckResponse_DeniedResponse{
					DeniedResponse: &authv3.DeniedHttpResponse{
						Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
						Body:   "A subject-scoped token is required",
					},
				},
			}, nil
		}
		decision, policyErr := s.authorizePolicies(ctx, result, access, nil, false, routePolicy)
		if policyErr != nil {
			reason := fmt.Sprintf("upstream policy failed: %v", policyErr)
			s.logAudit("deny", access.Method, host, access.Path, reason, tokenID)
			return policyErrorResponse(), nil
		}
		if !decision.Allow {
			s.logAudit("deny", access.Method, host, access.Path, decision.Reason, tokenID)
			return policyDeniedResponse(decision.Reason), nil
		}
		log.Printf("Identity verified for %s %s %s", access.Method, host, access.Path)
		s.logAudit("allow", access.Method, host, access.Path, "", tokenID)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{
				OkResponse: &authv3.OkHttpResponse{Headers: identityHeaderOptions(result)},
			},
		}, nil
	}
	if mode != "" && mode != "credential" {
		reason := fmt.Sprintf("unknown agent-creds route mode %q", mode)
		s.logAudit("deny", access.Method, host, access.Path, reason, tokenID)
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Body:   "Unknown agent-creds route mode",
				},
			},
		}, nil
	}

	if !hasConfiguredCredential {
		log.Printf("Auth failed: no credentials configured for %s", host)
		s.logAudit("deny", access.Method, host, access.Path, "no credentials configured for host", tokenID)
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
	decision, policyErr := s.authorizePolicies(ctx, result, access, &cred, true, routePolicy, cred.policy)
	if policyErr != nil {
		reason := fmt.Sprintf("upstream policy failed: %v", policyErr)
		log.Printf("%s", reason)
		s.logAudit("deny", access.Method, host, access.Path, reason, tokenID)
		return policyErrorResponse(), nil
	}
	if !decision.Allow {
		log.Printf("Upstream policy denied %s %s: %s", access.Method, host, decision.Reason)
		s.logAudit("deny", access.Method, host, access.Path, decision.Reason, tokenID)
		return policyDeniedResponse(decision.Reason), nil
	}

	providerResult, err := cred.provider.Resolve(ctx, provider.Request{
		Credential:     credentialKey,
		CredentialType: cred.credentialType,
		Host:           host,
		Method:         httpReq.GetMethod(),
		Path:           httpReq.GetPath(),
		Headers:        headers,
	})
	if err != nil {
		log.Printf("Credential resolution failed for %s: %v", host, err)
		s.logAudit("deny", access.Method, host, access.Path, fmt.Sprintf("credential resolution failed: %v", err), tokenID)
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
	if err := provider.ValidateHeaders(providerResult.Headers); err != nil {
		log.Printf("Credential resolution failed for %s: %v", host, err)
		s.logAudit("deny", access.Method, host, access.Path, fmt.Sprintf("credential resolution failed: %v", err), tokenID)
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
	s.logAudit("allow", access.Method, host, access.Path, "", tokenID)
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: credentialHeaderOptions(providerResult.Headers),
			},
		},
	}, nil
}

func (s *authServer) authorizePolicies(
	ctx context.Context,
	verified *macaroon.VerifyResult,
	access *macaroon.Access,
	credential *configuredCredential,
	requireForConstraints bool,
	names ...string,
) (policy.Decision, error) {
	constraints := make([]policy.Constraint, 0, len(verified.ApplicationConstraints))
	for _, caveat := range verified.ApplicationConstraints {
		constraints = append(constraints, policy.Constraint{
			Namespace: caveat.Namespace,
			Body:      caveat.Constraint,
		})
	}

	seen := make(map[string]bool)
	var selected []string
	for _, name := range names {
		name = strings.TrimPrefix(strings.TrimSpace(name), "/")
		if name != "" && !seen[name] {
			seen[name] = true
			selected = append(selected, name)
		}
	}
	if len(selected) == 0 {
		if requireForConstraints && len(constraints) > 0 {
			return policy.Deny("application-scoped token requires an upstream policy"), nil
		}
		return policy.Allow(), nil
	}

	request := policy.Request{
		Host:        access.Host,
		Method:      access.Method,
		Path:        access.Path,
		Subject:     verified.Subject,
		Constraints: constraints,
	}
	if credential != nil {
		request.Credential = credential.name
		request.CredentialType = credential.credentialType
	}
	for _, name := range selected {
		authorizer := s.policies[name]
		if authorizer == nil {
			return policy.Decision{}, fmt.Errorf("upstream policy %q is not configured", name)
		}
		request.Policy = name
		decision, err := authorizer.Authorize(ctx, request)
		if err != nil {
			return policy.Decision{}, fmt.Errorf("%s: %w", name, err)
		}
		if !decision.Allow {
			return decision, nil
		}
	}
	return policy.Allow(), nil
}

func policyDeniedResponse(reason string) *authv3.CheckResponse {
	if strings.TrimSpace(reason) == "" {
		reason = "request denied by upstream policy"
	}
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   "Forbidden: " + reason,
			},
		},
	}
}

func policyErrorResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.Internal)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_InternalServerError},
				Body:   "Upstream policy failed",
			},
		},
	}
}

func identityHeaderOptions(result *macaroon.VerifyResult) []*corev3.HeaderValueOption {
	headers := result.IdentityHeaders()
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	options := make([]*corev3.HeaderValueOption, 0, len(keys))
	for _, key := range keys {
		options = append(options, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: key, Value: headers[key]},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return options
}

func credentialHeaderOptions(headers map[string]string) []*corev3.HeaderValueOption {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	options := make([]*corev3.HeaderValueOption, 0, len(keys))
	for _, key := range keys {
		options = append(options, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   key,
				Value: headers[key],
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return options
}

// extractBuiltinCapabilityToken handles the authentication formats belonging
// to built-in providers. Service-specific schemes belong in JavaScript
// credential extractors instead of the verifier or this fallback.
func extractBuiltinCapabilityToken(header, prefix string) (string, bool) {
	if macaroon.IsMacaroonAuth(header, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")), true
	}
	if token := sigv4.ExtractAccessKey(header); strings.HasPrefix(token, prefix) {
		return token, true
	}
	if token := extractBasicAuthMacaroon(header, prefix); token != "" {
		return token, true
	}
	return "", false
}

// extractBasicAuthMacaroon extracts a macaroon token from a Basic auth header's password field.
// Returns the macaroon token if found, or empty string if not a Basic auth macaroon.
func extractBasicAuthMacaroon(header, prefix string) string {
	if !strings.HasPrefix(header, "Basic ") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return ""
	}
	// Format: username:password — macaroon is in the password
	_, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return ""
	}
	if strings.HasPrefix(password, prefix) {
		return password
	}
	return ""
}

func credentialExtractionErrorResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.Internal)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_InternalServerError},
				Body:   "Failed to extract credentials",
			},
		},
	}
}

func main() {
	// Load vault config (vault.yaml preferred, env vars as fallback)
	vaultPath := os.Getenv("VAULT_CONFIG")
	if vaultPath == "" {
		vaultPath = "vault.yaml"
	}

	vaultCfg, err := vault.Load(vaultPath)
	if errors.Is(err, os.ErrNotExist) {
		// Fallback: construct config from env vars for backward compatibility
		log.Printf("No vault.yaml found, falling back to env vars")
		vaultCfg = &vault.Config{
			SigningKey:    os.Getenv("MACAROON_SIGNING_KEY"),
			EncryptionKey: os.Getenv("MACAROON_ENCRYPTION_KEY"),
			Credentials:   make(map[string]vault.CredentialConfig),
		}
	} else if err != nil {
		log.Fatalf("Failed to load vault config %s: %v", vaultPath, err)
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
		log.Fatalf("Invalid vault config: %v", err)
	}
	for _, w := range warnings {
		log.Printf("Warning: %s", w)
	}

	verifier := macaroon.NewVerifier(keyStore)

	registry := provider.NewRegistry()
	if err := provider.RegisterBuiltins(registry); err != nil {
		log.Fatalf("Failed to register built-in credential providers: %v", err)
	}

	var jsSpecs []jsvm.Spec
	for name, credential := range vaultCfg.Credentials {
		if registry.Has(credential.Type) {
			continue
		}
		jsSpecs = append(jsSpecs, jsvm.Spec{
			Name:   name,
			Type:   credential.Type,
			Config: credential.ProviderConfig(),
		})
	}
	sort.Slice(jsSpecs, func(i, j int) bool {
		return jsSpecs[i].Name < jsSpecs[j].Name
	})
	var jsPolicySpecs []jsvm.PolicySpec
	for name, configuredPolicy := range vaultCfg.Policies {
		jsPolicySpecs = append(jsPolicySpecs, jsvm.PolicySpec{
			Name:   name,
			Type:   configuredPolicy.Type,
			Config: configuredPolicy.Config(),
		})
	}
	sort.Slice(jsPolicySpecs, func(i, j int) bool {
		return jsPolicySpecs[i].Name < jsPolicySpecs[j].Name
	})

	var jsManager *jsvm.Manager
	if len(jsSpecs) > 0 || len(jsPolicySpecs) > 0 {
		jsManager, err = jsvm.NewManagerWithPolicies(
			providerPaths(),
			providerPoolSize(),
			jsSpecs,
			jsPolicySpecs,
		)
		if err != nil {
			log.Fatalf("Failed to load JavaScript extensions: %v", err)
		}
	}

	policies := make(map[string]policy.Authorizer, len(jsPolicySpecs))
	for _, spec := range jsPolicySpecs {
		policies[spec.Name] = jsManager.Policy(spec)
		log.Printf("Loaded %s upstream policy for %s", spec.Type, spec.Name)
	}

	credentials := make(map[string]configuredCredential)
	for name, credential := range vaultCfg.Credentials {
		var credentialProvider provider.CredentialProvider
		var credentialExtractor provider.CredentialExtractor
		if registry.Has(credential.Type) {
			credentialProvider, err = registry.Build(credential.Type, credential.ProviderConfig())
		} else if jsManager != nil {
			spec := jsvm.Spec{
				Name:   name,
				Type:   credential.Type,
				Config: credential.ProviderConfig(),
			}
			credentialProvider = jsManager.Provider(spec)
			credentialExtractor = jsManager.Extractor(spec)
		} else {
			err = fmt.Errorf("credential provider %q is not registered", credential.Type)
		}
		if err != nil {
			log.Fatalf("Failed to configure credentials for %s: %v", name, err)
		}
		credentials[name] = configuredCredential{
			name:           name,
			credentialType: credential.Type,
			extractor:      credentialExtractor,
			provider:       credentialProvider,
			policy:         strings.TrimPrefix(credential.Policy, "/"),
		}
		log.Printf("Loaded %s credentials for %s", credential.Type, name)
	}

	if len(credentials) == 0 {
		log.Printf("Warning: No credentials configured in %s", vaultPath)
	}

	providerContext, stopProviders := context.WithCancel(context.Background())
	defer stopProviders()
	if jsManager != nil {
		jsManager.StartHotReload(providerContext)
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
			if n, err := database.DeleteOldAuditEntries(7 * 24 * time.Hour); err != nil {
				log.Printf("Audit log cleanup error: %v", err)
			} else if n > 0 {
				log.Printf("Cleaned up %d old audit log entries", n)
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

	apiServer, err := api.NewServer(database, keyStore, rpID, rpOrigin, rpName)
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
		verifier:    verifier,
		credentials: credentials,
		policies:    policies,
		strictMode:  strictMode,
		database:    database,
	})

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		stopProviders()
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

func providerPaths() []string {
	configured := strings.TrimSpace(os.Getenv("AGENT_CREDS_PROVIDER_PATH"))
	if configured == "" {
		return []string{"providers", "providers.d"}
	}
	return strings.FieldsFunc(configured, func(r rune) bool {
		return r == os.PathListSeparator
	})
}

func providerPoolSize() int {
	configured := strings.TrimSpace(os.Getenv("AGENT_CREDS_PROVIDER_POOL"))
	if configured == "" {
		return 0
	}
	size, err := strconv.Atoi(configured)
	if err != nil || size < 1 {
		log.Printf("Warning: invalid AGENT_CREDS_PROVIDER_POOL %q; using the default", configured)
		return 0
	}
	return size
}

// logAudit writes an audit entry asynchronously so it doesn't block the response path.
func (s *authServer) logAudit(decision, method, host, path, reason string, tokenID *string) {
	if s.database == nil {
		return
	}
	entry := &db.AuditEntry{
		Timestamp: time.Now(),
		Decision:  decision,
		Method:    method,
		Host:      host,
		Path:      path,
	}
	if reason != "" {
		entry.Reason = &reason
	}
	entry.TokenID = tokenID
	go func() {
		if err := s.database.InsertAuditEntry(entry); err != nil {
			log.Printf("Audit log error: %v", err)
		}
	}()
}

// extractTokenID attempts to extract the token UUID from a raw token string.
// Returns nil if the token cannot be decoded.
func extractTokenID(tokenStr string) *string {
	m, err := macaroon.DecodeToken(tokenStr)
	if err != nil {
		return nil
	}
	id := m.Nonce.UUID().String()
	return &id
}
