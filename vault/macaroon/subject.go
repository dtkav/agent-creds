package macaroon

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

// SubjectGetter is implemented by an access check that identifies its subject.
// A subject caveat fails closed when the access does not implement this
// interface or returns nil.
type SubjectGetter interface {
	GetSubject() *string
}

// SubjectCaveat restricts a token to one opaque subject.
type SubjectCaveat struct {
	Subject string `json:"subject"`
}

func (c *SubjectCaveat) CaveatType() macaroon.CaveatType { return CavSubject }
func (c *SubjectCaveat) Name() string                    { return "Subject" }

func (c *SubjectCaveat) Prohibits(access macaroon.Access) error {
	if err := ValidateSubject(c.Subject); err != nil {
		return fmt.Errorf("%w: %v", macaroon.ErrBadCaveat, err)
	}

	subjectAccess, ok := access.(SubjectGetter)
	if !ok {
		return fmt.Errorf("%w subject", resset.ErrResourceUnspecified)
	}

	subjectValue := subjectAccess.GetSubject()
	if subjectValue == nil {
		return fmt.Errorf("%w subject", resset.ErrResourceUnspecified)
	}

	subject := *subjectValue
	if err := ValidateSubject(subject); err != nil {
		return fmt.Errorf("%w: %v", macaroon.ErrInvalidAccess, err)
	}
	if subject != c.Subject {
		return fmt.Errorf("%w subject %q, only %q", resset.ErrUnauthorizedForResource, subject, c.Subject)
	}

	return nil
}

// NewSubjectCaveat validates subject and returns a caveat ready to add to a
// macaroon.
func NewSubjectCaveat(subject string) (*SubjectCaveat, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	return &SubjectCaveat{Subject: subject}, nil
}

// ValidateSubject validates an opaque subject before it is signed into a token
// or forwarded as an identity header. Subject meaning and formatting belong to
// the application that minted it.
func ValidateSubject(subject string) error {
	if subject == "" {
		return fmt.Errorf("subject must not be empty")
	}
	if strings.TrimSpace(subject) != subject {
		return fmt.Errorf("subject must not have surrounding whitespace")
	}
	if !utf8.ValidString(subject) {
		return fmt.Errorf("subject must be valid UTF-8")
	}
	for _, r := range subject {
		if unicode.IsControl(r) {
			return fmt.Errorf("subject must not contain control characters")
		}
	}
	return nil
}
