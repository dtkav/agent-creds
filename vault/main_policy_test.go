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
	verified := &tfmac.VerifyResult{ApplicationConstraints: []*tfmac.ApplicationConstraint{{
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
	subject := "customer-123"
	called := false
	server := &authServer{policies: map[string]policy.Authorizer{
		"records/read": policyFunc(func(_ context.Context, request policy.Request) (policy.Decision, error) {
			called = true
			if request.Subject == nil || *request.Subject != subject {
				t.Fatalf("subject = %#v", request.Subject)
			}
			if request.Credential != "records/prod" || request.CredentialType != "bearer" {
				t.Fatalf("credential context = %#v", request)
			}
			if len(request.Constraints) != 1 || request.Constraints[0].Namespace != "example" {
				t.Fatalf("constraints = %#v", request.Constraints)
			}
			return policy.Allow(), nil
		}),
	}}
	verified := &tfmac.VerifyResult{
		Subject: &subject,
		ApplicationConstraints: []*tfmac.ApplicationConstraint{{
			Namespace:  "example",
			Constraint: map[string]any{"services": []string{"records"}},
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
	verified := &tfmac.VerifyResult{ApplicationConstraints: []*tfmac.ApplicationConstraint{
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

func TestIdentityRouteCannotBypassAuthenticationThroughPassthrough(t *testing.T) {
	server := &authServer{verifier: tfmac.NewVerifier(&tfmac.KeyStore{
		SigningKey:  macaroon.NewSigningKey(),
		TokenPrefix: tfmac.DefaultTokenPrefix,
	})}
	response, err := server.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
				Method:  "POST",
				Path:    "/graphql",
				Headers: map[string]string{"host": "records.internal"},
			}},
			ContextExtensions: map[string]string{"agent_creds_mode": "identity"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("status = %#v", response.GetStatus())
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
				"agent_creds_mode": "credential",
				"credential":       "/github/test",
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
