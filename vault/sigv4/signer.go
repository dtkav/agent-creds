package sigv4

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Config holds the resolved SigV4 signing configuration
type Config struct {
	Region         string
	Service        string
	AccessKeyID    string
	SecretAccessKey string
}

// SignRequest re-signs a request with real AWS credentials.
// It builds a synthetic http.Request from the ext_authz attributes and signs it.
// pathWithQuery is the raw path from ext_authz GetPath() (includes query string).
// incomingHeaders are the original request headers from the client.
// Returns headers to set on the upstream request (authorization + x-amz-date).
func SignRequest(cfg *Config, method, host, pathWithQuery string, incomingHeaders map[string]string) (map[string]string, error) {
	// Parse path and query
	rawURL := "https://" + host + pathWithQuery
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Build synthetic request
	req := &http.Request{
		Method: method,
		URL:    u,
		Host:   host,
		Header: make(http.Header),
	}

	// Copy x-amz-* headers (except x-amz-date and x-amz-security-token which get regenerated)
	for k, v := range incomingHeaders {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "x-amz-") && lower != "x-amz-date" && lower != "x-amz-security-token" {
			req.Header.Set(k, v)
		}
	}

	// Copy content-type if present
	if ct, ok := incomingHeaders["content-type"]; ok {
		req.Header.Set("Content-Type", ct)
	}

	// Get payload hash from x-amz-content-sha256 (boto3 always sets this)
	payloadHash := incomingHeaders["x-amz-content-sha256"]
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	// Sign with real credentials
	creds := aws.Credentials{
		AccessKeyID:     cfg.AccessKeyID,
		SecretAccessKey: cfg.SecretAccessKey,
	}

	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), creds, req, payloadHash, cfg.Service, cfg.Region, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	result := map[string]string{
		"authorization": req.Header.Get("Authorization"),
		"x-amz-date":   req.Header.Get("X-Amz-Date"),
	}

	return result, nil
}

// ExtractAccessKey extracts the access key ID from a SigV4 Authorization header.
// Format: AWS4-HMAC-SHA256 Credential=AKID/date/region/service/aws4_request, ...
// Returns the access key ID or empty string if not a SigV4 header.
func ExtractAccessKey(authHeader string) string {
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return ""
	}

	// Find Credential= field
	idx := strings.Index(authHeader, "Credential=")
	if idx < 0 {
		return ""
	}

	// Extract value after "Credential="
	rest := authHeader[idx+len("Credential="):]

	// Access key ends at the first "/"
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return ""
	}

	return rest[:slashIdx]
}
