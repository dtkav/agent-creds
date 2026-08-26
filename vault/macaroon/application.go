package macaroon

import (
	"fmt"
	"strings"

	"github.com/superfly/macaroon"
	"github.com/vmihailenco/msgpack/v5"
)

// ApplicationConstraint carries an application-owned restriction through the
// public macaroon format. Agent-creds verifies its signature and structure,
// while the configured upstream policy interprets Constraint. Multiple
// constraints are conjunctive: a policy must accept every constraint in the
// token, including constraints appended during offline attenuation.
type ApplicationConstraint struct {
	Namespace  string         `json:"namespace" msgpack:"namespace"`
	Constraint map[string]any `json:"constraint" msgpack:"constraint"`
	// Authorized is set by the verifier when the constraint came from a
	// trusted third-party discharge. It is not part of the caveat wire format.
	Authorized bool `json:"-" msgpack:"-"`
}

func (c *ApplicationConstraint) CaveatType() macaroon.CaveatType { return CavApplication }
func (c *ApplicationConstraint) Name() string                    { return "ApplicationConstraint" }

// Prohibits performs only deployment-independent validation. The authoritative
// predicate runs later in the upstream policy, after the full macaroon has
// passed signature and core caveat verification.
func (c *ApplicationConstraint) Prohibits(macaroon.Access) error {
	return ValidateApplicationConstraint(c.Namespace, c.Constraint)
}

// EncodeMsgpack keeps map ordering stable because caveat bytes are part of the
// macaroon signature. It deliberately preserves the default two-element array
// wire shape used before this custom encoder was introduced.
func (c *ApplicationConstraint) EncodeMsgpack(encoder *msgpack.Encoder) error {
	return encodeApplicationConstraint(encoder, c.Namespace, c.Constraint)
}

func (c *ApplicationConstraint) DecodeMsgpack(decoder *msgpack.Decoder) error {
	return decodeApplicationConstraint(decoder, &c.Namespace, &c.Constraint)
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

func encodeApplicationConstraint(encoder *msgpack.Encoder, namespace string, constraint map[string]any) error {
	// SetSortMapKeys applies recursively and is harmless for the rest of this
	// caveat set. Without it, decoding and re-encoding a map-valued caveat can
	// produce different bytes and therefore an invalid signature.
	encoder.SetSortMapKeys(true)
	if err := encoder.EncodeArrayLen(2); err != nil {
		return err
	}
	if err := encoder.EncodeString(namespace); err != nil {
		return err
	}
	return encoder.Encode(constraint)
}

func decodeApplicationConstraint(decoder *msgpack.Decoder, namespace *string, constraint *map[string]any) error {
	length, err := decoder.DecodeArrayLen()
	if err != nil {
		return err
	}
	if length != 2 {
		return fmt.Errorf("application constraint must contain two fields, got %d", length)
	}
	if *namespace, err = decoder.DecodeString(); err != nil {
		return err
	}
	return decoder.Decode(constraint)
}
