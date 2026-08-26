package policy

import (
	"context"
	"strings"
)

// Constraint is an application-owned restriction from a verified macaroon.
// Policies must evaluate every constraint they receive conjunctively.
type Constraint struct {
	Namespace  string         `json:"namespace"`
	Body       map[string]any `json:"body"`
	Authorized bool           `json:"authorized"`
}

// Request is the verified request context presented to an upstream policy.
// Constraints originate only from the verified macaroon.
type Request struct {
	Policy         string
	PolicyType     string
	Host           string
	Method         string
	Path           string
	Body           []byte
	BodyPartial    bool
	Credential     string
	CredentialType string
	Constraints    []Constraint
}

type Decision struct {
	Allow  bool
	Reason string
}

type Authorizer interface {
	Authorize(context.Context, Request) (Decision, error)
}

func Deny(reason string) Decision {
	return Decision{Reason: strings.TrimSpace(reason)}
}

func Allow() Decision {
	return Decision{Allow: true}
}
