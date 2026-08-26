package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Request is the request context made available to a credential provider.
// Credential identifies the configured credential selected by the Envoy route;
// providers may further narrow execution by matching the remaining fields.
type Request struct {
	Credential     string
	CredentialType string
	Host           string
	Method         string
	Path           string
	Headers        map[string]string
	Body           []byte
	BodyPartial    bool
}

// Result contains the headers a provider wants Envoy to inject. ExpiresAt is
// optional; JavaScript registrations must separately opt into caching.
type Result struct {
	Headers   map[string]string
	ExpiresAt time.Time
	Stop      bool
}

// CredentialProvider resolves injection headers for one configured credential.
type CredentialProvider interface {
	Resolve(context.Context, Request) (Result, error)
}

// ExtractionRequest is the non-secret request context made available before
// capability verification. It intentionally has no provider configuration.
type ExtractionRequest struct {
	Credential     string
	CredentialType string
	Host           string
	Method         string
	Path           string
	Headers        map[string]string
}

// CredentialExtractor reads an unmodified client request and returns the
// agent-creds capability token it carries. Extractors run before token
// verification and therefore receive request facts only, never credential
// configuration or resolved secrets.
type CredentialExtractor interface {
	Extract(context.Context, ExtractionRequest) (string, error)
}

// Factory constructs a provider from its provider-specific configuration.
type Factory func(config map[string]any) (CredentialProvider, error)

// Registry maps public credential type names to provider factories.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

func (r *Registry) Register(name string, factory Factory) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("provider name must not be empty")
	}
	if factory == nil {
		return fmt.Errorf("provider %q has no factory", name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("provider %q is already registered", name)
	}
	r.factories[name] = factory
	return nil
}

func (r *Registry) Build(name string, config map[string]any) (CredentialProvider, error) {
	r.mu.RLock()
	factory := r.factories[name]
	r.mu.RUnlock()
	if factory == nil {
		return nil, fmt.Errorf("credential provider %q is not registered", name)
	}
	return factory(cloneMap(config))
}

func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.factories[name] != nil
}

// ValidateHeaders rejects values that cannot safely be copied into an HTTP
// response.
func ValidateHeaders(headers map[string]string) error {
	if len(headers) == 0 {
		return fmt.Errorf("provider returned no headers")
	}
	for name, value := range headers {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" {
			return fmt.Errorf("provider returned an empty header name")
		}
		if !validHeaderName(name) {
			return fmt.Errorf("provider returned invalid header name %q", name)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("provider returned a multiline value for header %q", name)
		}
	}
	return nil
}

func validHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
