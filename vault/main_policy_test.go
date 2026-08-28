package main

import (
	"context"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/superfly/macaroon"
	"google.golang.org/grpc/codes"

	tfmac "vault/macaroon"
	"vault/policy"
	"vault/provider"
)

type extractorFunc func(context.Context, provider.ExtractionRequest) (string, error)

func (f extractorFunc) Extract(ctx context.Context, request provider.ExtractionRequest) (string, error) {
	return f(ctx, request)
}

type providerFunc func(context.Context, provider.Request) (provider.Result, error)

func (f providerFunc) Resolve(ctx context.Context, request provider.Request) (provider.Result, error) {
	return f(ctx, request)
}

type policyFunc func(context.Context, policy.Request) (policy.Decision, error)

func (f policyFunc) Authorize(ctx context.Context, request policy.Request) (policy.Decision, error) {
	return f(ctx, request)
}

type testCredentialMacaroon struct {
	namespace  string
	authorize  policyFunc
	constraint *policy.Constraint
}

func (m testCredentialMacaroon) Namespace() string { return m.namespace }

func (m testCredentialMacaroon) Constraint(context.Context) (*policy.Constraint, error) {
	return m.constraint, nil
}

func (m testCredentialMacaroon) Authorize(ctx context.Context, request policy.Request) (policy.Decision, error) {
	return m.authorize(ctx, request)
}

func TestBufferedRequestBodyUsesRawBytesAndPartialMarker(t *testing.T) {
	request := &authv3.AttributeContext_HttpRequest{
		Body:    "text fallback",
		RawBody: []byte{0, 1, 2, 255},
		Headers: map[string]string{"x-envoy-auth-partial-body": "true"},
	}
	body, partial := bufferedRequestBody(request)
	request.RawBody[0] = 9
	if !partial {
		t.Fatal("partial body marker was ignored")
	}
	if len(body) != 4 || body[0] != 0 || body[3] != 255 {
		t.Fatalf("body = %#v", body)
	}
}

func TestBufferedRequestBodySupportsLegacyStringField(t *testing.T) {
	body, partial := bufferedRequestBody(&authv3.AttributeContext_HttpRequest{
		Body: "request body",
	})
	if partial || string(body) != "request body" {
		t.Fatalf("body = %q, partial = %v", body, partial)
	}
}

func TestCredentialRouteRejectsUnconsumedApplicationConstraints(t *testing.T) {
	server := &authServer{}
	verified := &tfmac.VerifyResult{ApplicationConstraints: []tfmac.VerifiedApplicationConstraint{{
		Namespace:  "example",
		Constraint: map[string]any{"services": []string{"records"}},
	}}}
	decision, err := server.authorizePolicies(
		context.Background(),
		verified,
		&tfmac.Access{Host: "records.example", Method: "GET", Path: "/", Timestamp: time.Now()},
		&configuredCredential{name: "records/prod", credentialType: "bearer"},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow {
		t.Fatal("credential route allowed an application constraint without a policy")
	}
}

func TestConfiguredPolicyReceivesVerifiedConstraints(t *testing.T) {
	called := false
	server := &authServer{policies: map[string]policy.Authorizer{
		"records/read": policyFunc(func(_ context.Context, request policy.Request) (policy.Decision, error) {
			called = true
			if request.Credential != "records/prod" || request.CredentialType != "bearer" {
				t.Fatalf("credential context = %#v", request)
			}
			if len(request.Constraints) != 1 || request.Constraints[0].Namespace != "example" {
				t.Fatalf("constraints = %#v", request.Constraints)
			}
			if request.Constraints[0].ThirdParty == nil || request.Constraints[0].ThirdParty.Location != "workflow-authorizer" {
				t.Fatalf("third-party provenance = %#v", request.Constraints[0].ThirdParty)
			}
			return policy.Allow(), nil
		}),
	}}
	verified := &tfmac.VerifyResult{
		ApplicationConstraints: []tfmac.VerifiedApplicationConstraint{{
			Namespace:  "example",
			Constraint: map[string]any{"services": []string{"records"}},
			ThirdParty: &tfmac.ThirdPartyProvenance{Location: "workflow-authorizer"},
		}},
	}
	decision, err := server.authorizePolicies(
		context.Background(),
		verified,
		&tfmac.Access{Host: "records.example", Method: "GET", Path: "/v1/items", Timestamp: time.Now()},
		&configuredCredential{name: "records/prod", credentialType: "bearer"},
		true,
		"/records/read",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !called || !decision.Allow {
		t.Fatalf("policy result = %#v, called = %v", decision, called)
	}
}

func TestCredentialMacaroonConsumesItsNamespaceBeforeExplicitPolicy(t *testing.T) {
	credentialCalled := false
	explicitCalled := false
	credential := &configuredCredential{
		name:           "github/prod",
		credentialType: "github",
		macaroon: testCredentialMacaroon{
			namespace: "github",
			authorize: func(_ context.Context, request policy.Request) (policy.Decision, error) {
				credentialCalled = true
				if len(request.Constraints) != 1 || request.Constraints[0].Namespace != "github" {
					t.Fatalf("credential constraints = %#v", request.Constraints)
				}
				return policy.Allow(), nil
			},
		},
	}
	server := &authServer{policies: map[string]policy.Authorizer{
		"deployment/extra": policyFunc(func(_ context.Context, request policy.Request) (policy.Decision, error) {
			explicitCalled = true
			if len(request.Constraints) != 1 || request.Constraints[0].Namespace != "deployment" {
				t.Fatalf("explicit policy constraints = %#v", request.Constraints)
			}
			return policy.Allow(), nil
		}),
	}}
	verified := &tfmac.VerifyResult{ApplicationConstraints: []tfmac.VerifiedApplicationConstraint{
		{Namespace: "github", Constraint: map[string]any{"branches": []any{"agent/work"}}},
		{Namespace: "deployment", Constraint: map[string]any{"environment": "prod"}},
	}}
	decision, err := server.authorizePolicies(
		context.Background(),
		verified,
		&tfmac.Access{Host: "github.com", Method: "POST", Path: "/repo.git/git-receive-pack", Timestamp: time.Now()},
		credential,
		true,
		"deployment/extra",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow || !credentialCalled || !explicitCalled {
		t.Fatalf("decision = %#v, credential called = %v, explicit called = %v", decision, credentialCalled, explicitCalled)
	}
}

func TestCredentialMacaroonEnforcesConfigWithoutSignedConstraint(t *testing.T) {
	credential := &configuredCredential{
		name:           "github/prod",
		credentialType: "github",
		macaroon: testCredentialMacaroon{
			namespace: "github",
			authorize: func(_ context.Context, request policy.Request) (policy.Decision, error) {
				if len(request.Constraints) != 0 {
					t.Fatalf("constraints = %#v", request.Constraints)
				}
				return policy.Deny("current credential config denied the request"), nil
			},
		},
	}
	decision, err := (&authServer{}).authorizePolicies(
		context.Background(),
		&tfmac.VerifyResult{},
		&tfmac.Access{Host: "github.com", Method: "POST", Path: "/repo.git/git-receive-pack", Timestamp: time.Now()},
		credential,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.Reason == "" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestRoutePolicyCannotBypassAuthenticationThroughPassthrough(t *testing.T) {
	server := &authServer{verifier: tfmac.NewVerifier(&tfmac.KeyStore{
		SigningKey:  macaroon.NewSigningKey(),
		TokenPrefix: tfmac.DefaultTokenPrefix,
	})}
	response, err := server.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
				Method:  "GET",
				Path:    "/v1/items",
				Headers: map[string]string{"host": "records.internal"},
			}},
			ContextExtensions: map[string]string{"policy": "/records/read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("status = %#v", response.GetStatus())
	}
}

func TestCredentialMacaroonRequiresCapabilityAndProviderMayPreserveBearer(t *testing.T) {
	store := &tfmac.KeyStore{
		SigningKey:  macaroon.NewSigningKey(),
		KeyID:       []byte("horizontal-test"),
		TokenPrefix: tfmac.DefaultTokenPrefix,
	}
	token, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := tfmac.NewApplicationConstraint("horizontal-test", map[string]any{
		"grants": []any{map[string]any{"host": "bff.internal"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := token.Add(constraint); err != nil {
		t.Fatal(err)
	}
	encoded, err := tfmac.EncodeToken(token)
	if err != nil {
		t.Fatal(err)
	}

	authorizerCalled := false
	server := &authServer{
		verifier: tfmac.NewVerifier(store),
		credentials: map[string]configuredCredential{
			"sandbox/horizontal": {
				name:           "sandbox/horizontal",
				credentialType: "horizontal-test",
				macaroon: testCredentialMacaroon{
					namespace: "horizontal-test",
					authorize: func(_ context.Context, request policy.Request) (policy.Decision, error) {
						authorizerCalled = true
						if request.Host != "bff.internal" || len(request.Constraints) != 1 {
							t.Fatalf("authorization request = %#v", request)
						}
						return policy.Allow(), nil
					},
				},
				provider: providerFunc(func(_ context.Context, request provider.Request) (provider.Result, error) {
					return provider.Result{
						Headers: map[string]string{"authorization": request.Headers["authorization"]},
						Stop:    false,
					}, nil
				}),
			},
		},
	}

	check := func(authorization string) *authv3.CheckResponse {
		t.Helper()
		headers := map[string]string{"host": "bff.internal"}
		if authorization != "" {
			headers["authorization"] = authorization
		}
		response, checkErr := server.Check(context.Background(), &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
					Method:  "POST",
					Path:    "/graphql",
					Headers: headers,
				}},
				ContextExtensions: map[string]string{"credential": "/sandbox/horizontal"},
			},
		})
		if checkErr != nil {
			t.Fatal(checkErr)
		}
		return response
	}

	if response := check(""); response.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("missing capability status = %#v", response.GetStatus())
	}
	if response := check("Bearer acm_invalid"); response.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("invalid capability status = %#v", response.GetStatus())
	}
	response := check("Bearer " + encoded)
	if response.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("valid capability status = %#v", response.GetStatus())
	}
	if !authorizerCalled {
		t.Fatal("credential macaroon authorizer was not called")
	}
	if headers := response.GetOkResponse().GetHeaders(); len(headers) != 1 || headers[0].GetHeader().GetValue() != "Bearer "+encoded {
		t.Fatalf("pass-through credential headers = %#v", headers)
	}
}

func TestCredentialProviderCanContinueToHostCredential(t *testing.T) {
	store := &tfmac.KeyStore{
		SigningKey:  macaroon.NewSigningKey(),
		KeyID:       []byte("horizontal-cross-route-test"),
		TokenPrefix: tfmac.DefaultTokenPrefix,
	}
	token, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := tfmac.NewApplicationConstraint("horizontal-cross-route", map[string]any{
		"grants": []any{
			map[string]any{
				"host":    "records.internal",
				"methods": []any{"GET"},
				"paths":   []any{"/v1/accounts/account_1"},
			},
			map[string]any{
				"host":    "raw.internal",
				"methods": []any{"GET"},
				"paths":   []any{"/v1/accounts/account_1"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	subject, err := tfmac.NewApplicationConstraint(
		"horizontal-cross-route",
		map[string]any{"subject": "account:account_1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, caveat := range []macaroon.Caveat{grant, subject} {
		if err := token.Add(caveat); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := tfmac.EncodeToken(token)
	if err != nil {
		t.Fatal(err)
	}

	horizontalCalls := 0
	egressCalls := 0
	rawResolved := false
	server := &authServer{
		verifier: tfmac.NewVerifier(store),
		credentials: map[string]configuredCredential{
			"sandbox/session": {
				name:           "sandbox/session",
				credentialType: "horizontal-cross-route",
				macaroon: testCredentialMacaroon{
					namespace: "horizontal-cross-route",
					authorize: func(_ context.Context, request policy.Request) (policy.Decision, error) {
						horizontalCalls++
						if request.Host == "bff.internal" && request.Method == "POST" && request.Path == "/graphql" {
							return policy.Allow(), nil
						}
						if (request.Host != "records.internal" && request.Host != "raw.internal") || request.Method != "GET" {
							return policy.Deny("outside horizontal grant"), nil
						}
						if len(request.Constraints) != 2 {
							return policy.Deny("horizontal constraints missing"), nil
						}
						return policy.Allow(), nil
					},
				},
				provider: providerFunc(func(_ context.Context, request provider.Request) (provider.Result, error) {
					return provider.Result{
						Headers: map[string]string{"authorization": request.Headers["authorization"]},
						Stop:    false,
					}, nil
				}),
			},
			"records.internal": {
				name:           "records.internal",
				credentialType: "records-test",
				macaroon: testCredentialMacaroon{
					namespace: "horizontal-cross-route",
					authorize: func(_ context.Context, request policy.Request) (policy.Decision, error) {
						egressCalls++
						if request.Host != "records.internal" || request.Method != "GET" || request.Path != "/v1/accounts/account_1" {
							return policy.Deny("outside record grant or subject"), nil
						}
						if len(request.Constraints) != 2 {
							return policy.Deny("egress constraints missing"), nil
						}
						return policy.Allow(), nil
					},
				},
				provider: providerFunc(func(context.Context, provider.Request) (provider.Result, error) {
					return provider.Result{Headers: map[string]string{
						"authorization": "Bearer upstream-secret",
					}, Stop: true}, nil
				}),
			},
			"raw.internal": {
				name:           "raw.internal",
				credentialType: "bearer",
				provider: providerFunc(func(context.Context, provider.Request) (provider.Result, error) {
					rawResolved = true
					return provider.Result{Headers: map[string]string{
						"authorization": "Bearer must-not-be-injected",
					}, Stop: true}, nil
				}),
			},
		},
	}

	check := func(credential, host, method, path string) *authv3.CheckResponse {
		t.Helper()
		response, checkErr := server.Check(context.Background(), &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
					Method: method,
					Path:   path,
					Headers: map[string]string{
						"host":          host,
						"authorization": "Bearer " + encoded,
					},
				}},
				ContextExtensions: map[string]string{"credential": credential},
			},
		})
		if checkErr != nil {
			t.Fatal(checkErr)
		}
		return response
	}

	ingress := check("/sandbox/session", "bff.internal", "POST", "/graphql")
	if ingress.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("BFF ingress status = %#v", ingress.GetStatus())
	}
	if headers := ingress.GetOkResponse().GetHeaders(); len(headers) != 1 || headers[0].GetHeader().GetValue() != "Bearer "+encoded {
		t.Fatalf("BFF ingress did not preserve the bearer: %#v", headers)
	}

	egress := check("/sandbox/session", "records.internal", "GET", "/v1/accounts/account_1")
	if egress.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("records egress status = %#v", egress.GetStatus())
	}
	if headers := egress.GetOkResponse().GetHeaders(); len(headers) != 1 || headers[0].GetHeader().GetValue() != "Bearer upstream-secret" {
		t.Fatalf("records egress headers = %#v", headers)
	}

	denied := check("/sandbox/session", "records.internal", "GET", "/v1/accounts/account_2")
	if denied.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("cross-subject egress status = %#v", denied.GetStatus())
	}
	nonConsuming := check("/sandbox/session", "raw.internal", "GET", "/v1/accounts/account_1")
	if nonConsuming.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("non-consuming host credential status = %#v", nonConsuming.GetStatus())
	}
	if rawResolved {
		t.Fatal("non-consuming host credential resolved before authorization")
	}
	if horizontalCalls != 4 || egressCalls != 2 {
		t.Fatalf("authorizer calls: horizontal=%d egress=%d", horizontalCalls, egressCalls)
	}
}

func TestPolicyOnlyRoutePreservesVerifiedBearerToken(t *testing.T) {
	store := &tfmac.KeyStore{
		SigningKey:  macaroon.NewSigningKey(),
		KeyID:       []byte("policy-only-test"),
		TokenPrefix: tfmac.DefaultTokenPrefix,
	}
	token, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := token.Add(&tfmac.HostCaveat{Hosts: []string{"records.internal"}}); err != nil {
		t.Fatal(err)
	}
	constraint, err := tfmac.NewApplicationConstraint("records", map[string]any{"subject": "operator@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := token.Add(constraint); err != nil {
		t.Fatal(err)
	}
	encoded, err := tfmac.EncodeToken(token)
	if err != nil {
		t.Fatal(err)
	}

	server := &authServer{
		verifier: tfmac.NewVerifier(store),
		policies: map[string]policy.Authorizer{
			"records/read": policyFunc(func(_ context.Context, request policy.Request) (policy.Decision, error) {
				if request.Credential != "" || request.CredentialType != "" {
					t.Fatalf("policy-only request selected a credential: %#v", request)
				}
				if len(request.Constraints) != 1 || request.Constraints[0].Namespace != "records" {
					t.Fatalf("constraints = %#v", request.Constraints)
				}
				return policy.Allow(), nil
			}),
		},
	}
	response, err := server.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
				Method: "GET",
				Path:   "/v1/items",
				Headers: map[string]string{
					"host":          "records.internal",
					"authorization": "Bearer " + encoded,
				},
			}},
			ContextExtensions: map[string]string{"policy": "/records/read"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("status = %#v", response.GetStatus())
	}
	if headers := response.GetOkResponse().GetHeaders(); len(headers) != 0 {
		t.Fatalf("policy-only route mutated headers: %#v", headers)
	}
}

func TestInvalidExtractedTokenNeverReachesCredentialProvider(t *testing.T) {
	extractorCalled := false
	providerCalled := false
	server := &authServer{
		verifier: tfmac.NewVerifier(&tfmac.KeyStore{
			SigningKey:  macaroon.NewSigningKey(),
			TokenPrefix: tfmac.DefaultTokenPrefix,
		}),
		credentials: map[string]configuredCredential{
			"github/test": {
				name:           "github/test",
				credentialType: "github",
				extractor: extractorFunc(func(context.Context, provider.ExtractionRequest) (string, error) {
					extractorCalled = true
					return "acm_not-a-valid-token", nil
				}),
				provider: providerFunc(func(context.Context, provider.Request) (provider.Result, error) {
					providerCalled = true
					return provider.Result{Headers: map[string]string{"authorization": "secret"}}, nil
				}),
			},
		},
		strictMode: true,
	}
	response, err := server.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
				Method:  "GET",
				Path:    "/user",
				Headers: map[string]string{"host": "api.github.com"},
			}},
			ContextExtensions: map[string]string{
				"credential": "/github/test",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !extractorCalled {
		t.Fatal("credential extractor was not called")
	}
	if providerCalled {
		t.Fatal("credential provider ran before capability verification")
	}
	if response.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("status = %#v", response.GetStatus())
	}
}

func TestServiceSpecificAuthorizationSchemeIsNotBuiltIntoGo(t *testing.T) {
	if token, ok := extractBuiltinCapabilityToken("token acm_service-specific", "acm_"); ok {
		t.Fatalf("built-in extractor accepted service-specific token scheme: %q", token)
	}
}
