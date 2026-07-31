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
)

type policyFunc func(context.Context, policy.Request) (policy.Decision, error)

func (f policyFunc) Authorize(ctx context.Context, request policy.Request) (policy.Decision, error) {
	return f(ctx, request)
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
