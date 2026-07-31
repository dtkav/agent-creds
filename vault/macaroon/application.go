package macaroon

import (
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
)

// ApplicationConstraint carries an application-owned restriction through the
// public macaroon format. Agent-creds verifies its signature and structure,
// while the configured upstream policy interprets Constraint. Multiple
// constraints are conjunctive: a policy must accept every constraint in the
// token, including constraints appended during offline attenuation.
type ApplicationConstraint struct {
	Namespace  string         `json:"namespace" msgpack:"namespace"`
	Constraint map[string]any `json:"constraint" msgpack:"constraint"`
}

func (c *ApplicationConstraint) CaveatType() macaroon.CaveatType { return CavApplication }
func (c *ApplicationConstraint) Name() string                    { return "ApplicationConstraint" }

// Prohibits performs only deployment-independent validation. The authoritative
// predicate runs later in the upstream policy, after the full macaroon has
// passed signature and core caveat verification.
func (c *ApplicationConstraint) Prohibits(macaroon.Access) error {
	return ValidateApplicationConstraint(c.Namespace, c.Constraint)
}

func ValidateApplicationConstraint(namespace string, constraint map[string]any) error {
	if namespace == "" {
		return fmt.Errorf("application constraint namespace must not be empty")
	}
	if strings.TrimSpace(namespace) != namespace {
		return fmt.Errorf("application constraint namespace must not have surrounding whitespace")
	}
	if constraint == nil {
		return fmt.Errorf("application constraint body must not be null")
	}
	return nil
}

func NewApplicationConstraint(namespace string, constraint map[string]any) (*ApplicationConstraint, error) {
	if err := ValidateApplicationConstraint(namespace, constraint); err != nil {
		return nil, err
	}
	return &ApplicationConstraint{Namespace: namespace, Constraint: constraint}, nil
}
