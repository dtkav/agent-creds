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

// ApplicationAttestation is an arbitrary namespaced value asserted by a
// trusted third party. The macaroon library permits attestations only in a
// proof discharge, finalizes that proof on encoding, and excludes attestations
// from discharges whose location is not trusted by the verifier.
type ApplicationAttestation struct {
	Namespace   string         `json:"namespace" msgpack:"namespace"`
	Attestation map[string]any `json:"attestation" msgpack:"attestation"`
}

func (c *ApplicationAttestation) CaveatType() macaroon.CaveatType {
	return CavApplicationAttestation
}
func (c *ApplicationAttestation) Name() string        { return "ApplicationAttestation" }
func (c *ApplicationAttestation) IsAttestation() bool { return true }
func (c *ApplicationAttestation) Prohibits(macaroon.Access) error {
	return ValidateApplicationConstraint(c.Namespace, c.Attestation)
}
func (c *ApplicationAttestation) EncodeMsgpack(encoder *msgpack.Encoder) error {
	return encodeApplicationConstraint(encoder, c.Namespace, c.Attestation)
}
func (c *ApplicationAttestation) DecodeMsgpack(decoder *msgpack.Decoder) error {
	return decodeApplicationConstraint(decoder, &c.Namespace, &c.Attestation)
}

func NewApplicationAttestation(namespace string, body map[string]any) (*ApplicationAttestation, error) {
	if err := ValidateApplicationConstraint(namespace, body); err != nil {
		return nil, err
	}
	return &ApplicationAttestation{Namespace: namespace, Attestation: body}, nil
}

// ApplicationAttestationRequirement is an attenuating first-party caveat. It
// requires at least one application attestation with the given namespace from
// the named third-party location. It says nothing about the attestation body;
// the selected credential or policy owns those semantics.
type ApplicationAttestationRequirement struct {
	Namespace string `json:"namespace" msgpack:"namespace"`
	Location  string `json:"location" msgpack:"location"`
}

func (c *ApplicationAttestationRequirement) CaveatType() macaroon.CaveatType {
	return CavApplicationRequired
}
func (c *ApplicationAttestationRequirement) Name() string {
	return "ApplicationAttestationRequirement"
}
func (c *ApplicationAttestationRequirement) Prohibits(macaroon.Access) error {
	if strings.TrimSpace(c.Namespace) != c.Namespace || c.Namespace == "" {
		return fmt.Errorf("required application attestation namespace must be non-empty without surrounding whitespace")
	}
	if strings.TrimSpace(c.Location) != c.Location || c.Location == "" {
		return fmt.Errorf("required third-party location must be non-empty without surrounding whitespace")
	}
	return nil
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
