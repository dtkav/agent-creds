package macaroon

import (
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
	"github.com/vmihailenco/msgpack/v5"
)

// AuthorizationRequest is encrypted into a third-party caveat ticket. It
// tells the discharger which configured credential and provider namespace the
// holder is asking it to authorize.
type AuthorizationRequest struct {
	Credential string `json:"credential" msgpack:"credential"`
	Namespace  string `json:"namespace" msgpack:"namespace"`
	Authorizer string `json:"authorizer" msgpack:"authorizer"`
}

func (c *AuthorizationRequest) CaveatType() macaroon.CaveatType { return CavAuthorizationRequest }
func (c *AuthorizationRequest) Name() string                    { return "AuthorizationRequest" }
func (c *AuthorizationRequest) Prohibits(macaroon.Access) error {
	return ValidateAuthorizationRequest(c.Credential, c.Namespace, c.Authorizer)
}

func ValidateAuthorizationRequest(credential, namespace, authorizer string) error {
	if strings.TrimSpace(credential) != credential || !strings.HasPrefix(credential, "/") || credential == "/" {
		return fmt.Errorf("authorization credential must be an absolute Vault path")
	}
	if strings.TrimSpace(namespace) != namespace || namespace == "" {
		return fmt.Errorf("authorization namespace must be non-empty without surrounding whitespace")
	}
	if strings.TrimSpace(authorizer) != authorizer || authorizer == "" {
		return fmt.Errorf("authorization authorizer must be non-empty without surrounding whitespace")
	}
	return nil
}

// ApplicationConstraintRequirement is placed on the primary macaroon. A
// matching provider constraint must be present after all discharge macaroons
// have been verified, preventing an empty discharge from satisfying an
// authorization-bearing capability.
type ApplicationConstraintRequirement struct {
	Namespace string `json:"namespace" msgpack:"namespace"`
}

// AuthorizedApplicationConstraint is an attestation produced only inside a
// trusted third-party discharge. Unlike ApplicationConstraint, a bearer cannot
// append one while attenuating the primary macaroon.
type AuthorizedApplicationConstraint struct {
	Namespace  string         `json:"namespace" msgpack:"namespace"`
	Constraint map[string]any `json:"constraint" msgpack:"constraint"`
}

func (c *AuthorizedApplicationConstraint) CaveatType() macaroon.CaveatType {
	return CavAuthorizedApplication
}
func (c *AuthorizedApplicationConstraint) Name() string        { return "AuthorizedApplicationConstraint" }
func (c *AuthorizedApplicationConstraint) IsAttestation() bool { return true }
func (c *AuthorizedApplicationConstraint) Prohibits(macaroon.Access) error {
	return ValidateApplicationConstraint(c.Namespace, c.Constraint)
}
func (c *AuthorizedApplicationConstraint) EncodeMsgpack(encoder *msgpack.Encoder) error {
	return encodeApplicationConstraint(encoder, c.Namespace, c.Constraint)
}
func (c *AuthorizedApplicationConstraint) DecodeMsgpack(decoder *msgpack.Decoder) error {
	return decodeApplicationConstraint(decoder, &c.Namespace, &c.Constraint)
}

func NewAuthorizedApplicationConstraint(namespace string, constraint map[string]any) (*AuthorizedApplicationConstraint, error) {
	if err := ValidateApplicationConstraint(namespace, constraint); err != nil {
		return nil, err
	}
	return &AuthorizedApplicationConstraint{Namespace: namespace, Constraint: constraint}, nil
}

func (c *ApplicationConstraintRequirement) CaveatType() macaroon.CaveatType {
	return CavApplicationRequired
}
func (c *ApplicationConstraintRequirement) Name() string { return "ApplicationConstraintRequirement" }
func (c *ApplicationConstraintRequirement) Prohibits(macaroon.Access) error {
	if strings.TrimSpace(c.Namespace) != c.Namespace || c.Namespace == "" {
		return fmt.Errorf("required application constraint namespace must be non-empty without surrounding whitespace")
	}
	return nil
}
