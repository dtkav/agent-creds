package macaroon

import (
	"errors"
	"testing"
	"time"

	supermac "github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

type subjectAccess struct {
	subject *string
}

func (a *subjectAccess) Now() time.Time      { return time.Now() }
func (a *subjectAccess) Validate() error     { return nil }
func (a *subjectAccess) GetSubject() *string { return a.subject }

func subjectPtr(subject string) *string {
	return &subject
}

func TestValidateSubject(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		wantErr bool
	}{
		{name: "opaque id", subject: "01JABC"},
		{name: "opaque id may contain colon", subject: "external:123"},
		{name: "unicode", subject: "customer-世界"},
		{name: "empty", subject: "", wantErr: true},
		{name: "surrounding whitespace", subject: " subject-123", wantErr: true},
		{name: "newline", subject: "subject\n123", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSubject(tt.subject)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateSubject(%q) succeeded, want error", tt.subject)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateSubject(%q): %v", tt.subject, err)
			}
		})
	}
}

func TestSubjectCaveatProhibits(t *testing.T) {
	caveat := &SubjectCaveat{Subject: "subject-guid"}

	if err := caveat.Prohibits(&subjectAccess{subject: subjectPtr("subject-guid")}); err != nil {
		t.Fatalf("matching subject prohibited: %v", err)
	}

	err := caveat.Prohibits(&subjectAccess{subject: subjectPtr("other")})
	if !errors.Is(err, resset.ErrUnauthorizedForResource) {
		t.Fatalf("mismatched subject error = %v, want ErrUnauthorizedForResource", err)
	}

	err = caveat.Prohibits(&subjectAccess{})
	if !errors.Is(err, resset.ErrResourceUnspecified) {
		t.Fatalf("missing subject error = %v, want ErrResourceUnspecified", err)
	}

	err = caveat.Prohibits(&Access{Host: "example.com", Method: "GET", Path: "/"})
	if !errors.Is(err, resset.ErrResourceUnspecified) {
		t.Fatalf("access without subject support error = %v, want ErrResourceUnspecified", err)
	}

	badCaveat := &SubjectCaveat{Subject: "bad\nsubject"}
	err = badCaveat.Prohibits(&subjectAccess{subject: subjectPtr("subject-guid")})
	if !errors.Is(err, supermac.ErrBadCaveat) {
		t.Fatalf("invalid caveat error = %v, want ErrBadCaveat", err)
	}

	err = caveat.Prohibits(&subjectAccess{subject: subjectPtr("bad\nsubject")})
	if !errors.Is(err, supermac.ErrInvalidAccess) {
		t.Fatalf("invalid access error = %v, want ErrInvalidAccess", err)
	}
}

func TestSubjectCaveatMacaroonRoundTrip(t *testing.T) {
	key := supermac.NewSigningKey()
	m, err := supermac.New([]byte("test-key"), TokenLocation, key)
	if err != nil {
		t.Fatal(err)
	}

	caveat, err := NewSubjectCaveat("subject-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Add(caveat); err != nil {
		t.Fatal(err)
	}

	token, err := EncodeToken(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := decoded.Verify(key, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	subjects := supermac.GetCaveats[*SubjectCaveat](verified)
	if len(subjects) != 1 || subjects[0].Subject != "subject-123" {
		t.Fatalf("decoded subjects = %#v", subjects)
	}
	if err := verified.Validate(&subjectAccess{subject: subjectPtr("subject-123")}); err != nil {
		t.Fatalf("matching decoded subject prohibited: %v", err)
	}
}
