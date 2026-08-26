package macaroon

import (
	"fmt"
	"time"
)

// Access represents an HTTP request to an API endpoint.
// It implements the superfly/macaroon.Access interface.
type Access struct {
	// Host is the target API host (e.g., "api.stripe.com")
	Host string

	// Method is the HTTP method (GET, POST, PUT, DELETE, etc.)
	Method string

	// Path is the request path (e.g., "/v1/customers/cus_123")
	Path string

	// Timestamp is when the request was made
	Timestamp time.Time
}

// Now returns the request timestamp (required by macaroon.Access interface)
func (a *Access) Now() time.Time {
	if a.Timestamp.IsZero() {
		return time.Now()
	}
	return a.Timestamp
}

// Validate checks that the Access is well-formed (required by macaroon.Access interface)
func (a *Access) Validate() error {
	if a.Host == "" {
		return fmt.Errorf("host is required")
	}
	if a.Method == "" {
		return fmt.Errorf("method is required")
	}
	if a.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}

// GetHost returns the target host
func (a *Access) GetHost() string {
	return a.Host
}

// GetMethod returns the HTTP method
func (a *Access) GetMethod() string {
	return a.Method
}

// GetPath returns the request path
func (a *Access) GetPath() string {
	return a.Path
}
