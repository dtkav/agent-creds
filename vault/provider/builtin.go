package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"vault/oauth2"
	"vault/sigv4"
)

// RegisterBuiltins registers the credential providers shipped with the public
// Vault binary.
func RegisterBuiltins(registry *Registry) error {
	oauthTokens := oauth2.NewTokenManager()
	registrations := []struct {
		name    string
		factory Factory
	}{
		{"bearer", newBearerProvider},
		{"header", newHeaderProvider},
		{"basic", newBasicProvider},
		{"oauth2", newOAuth2Factory(oauthTokens)},
		{"sigv4", newSigV4Provider},
	}
	for _, registration := range registrations {
		if err := registry.Register(registration.name, registration.factory); err != nil {
			return err
		}
	}
	return nil
}

type staticProvider struct {
	headers map[string]string
}

func (p *staticProvider) Resolve(context.Context, Request) (Result, error) {
	headers := make(map[string]string, len(p.headers))
	for name, value := range p.headers {
		headers[name] = value
	}
	return Result{Headers: headers, Stop: true}, nil
}

func newBearerProvider(config map[string]any) (CredentialProvider, error) {
	token, err := requiredString(config, "token")
	if err != nil {
		return nil, err
	}
	return newStaticHeaderProvider("authorization", "Bearer "+token)
}

func newHeaderProvider(config map[string]any) (CredentialProvider, error) {
	header, err := requiredString(config, "header")
	if err != nil {
		return nil, err
	}
	value, err := requiredString(config, "value")
	if err != nil {
		return nil, err
	}
	return newStaticHeaderProvider(header, value)
}

func newStaticHeaderProvider(header, value string) (CredentialProvider, error) {
	header = strings.ToLower(strings.TrimSpace(header))
	if !validHeaderName(header) {
		return nil, fmt.Errorf("header must be a valid HTTP header name")
	}
	if unsafeCredentialHeader(header) {
		return nil, fmt.Errorf("header %q may not be set by a credential provider", header)
	}

	headers := map[string]string{header: value}
	if err := ValidateHeaders(headers); err != nil {
		return nil, err
	}
	return &staticProvider{headers: headers}, nil
}

func unsafeCredentialHeader(header string) bool {
	switch header {
	case "connection", "content-length", "host", "keep-alive",
		"proxy-authorization", "proxy-connection", "te", "trailer",
		"transfer-encoding", "upgrade", "x-target-host":
		return true
	default:
		return false
	}
}

func newBasicProvider(config map[string]any) (CredentialProvider, error) {
	username, err := requiredString(config, "username")
	if err != nil {
		return nil, err
	}
	password, err := configuredString(config, "password", true)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return &staticProvider{headers: map[string]string{
		"authorization": "Basic " + encoded,
	}}, nil
}

type sigV4Provider struct {
	config *sigv4.Config
}

type oauth2Provider struct {
	config  *oauth2.OAuth2Config
	manager *oauth2.TokenManager
}

func newOAuth2Factory(manager *oauth2.TokenManager) Factory {
	return func(config map[string]any) (CredentialProvider, error) {
		clientID, err := requiredString(config, "client_id")
		if err != nil {
			return nil, err
		}
		clientSecret, err := requiredString(config, "client_secret")
		if err != nil {
			return nil, err
		}
		refreshToken, err := requiredString(config, "refresh_token")
		if err != nil {
			return nil, err
		}
		tokenURL, err := requiredString(config, "token_url")
		if err != nil {
			return nil, err
		}
		return &oauth2Provider{
			config: &oauth2.OAuth2Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RefreshToken: refreshToken,
				TokenURL:     tokenURL,
			},
			manager: manager,
		}, nil
	}
}

func (p *oauth2Provider) Resolve(_ context.Context, request Request) (Result, error) {
	cacheKey := request.Credential
	if cacheKey == "" {
		cacheKey = request.Host
	}
	token, err := p.manager.GetAccessToken(cacheKey, p.config)
	if err != nil {
		return Result{}, err
	}
	return Result{Headers: map[string]string{
		"authorization": "Bearer " + token,
	}, Stop: true}, nil
}

func newSigV4Provider(config map[string]any) (CredentialProvider, error) {
	region, err := requiredString(config, "region")
	if err != nil {
		return nil, err
	}
	service, err := requiredString(config, "service")
	if err != nil {
		return nil, err
	}
	accessKeyID, err := requiredString(config, "access_key_id")
	if err != nil {
		return nil, err
	}
	secretAccessKey, err := requiredString(config, "secret_access_key")
	if err != nil {
		return nil, err
	}
	return &sigV4Provider{config: &sigv4.Config{
		Region:          region,
		Service:         service,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}}, nil
}

func (p *sigV4Provider) Resolve(_ context.Context, request Request) (Result, error) {
	headers, err := sigv4.SignRequest(
		p.config,
		request.Method,
		request.Host,
		request.Path,
		request.Headers,
	)
	if err != nil {
		return Result{}, err
	}
	return Result{Headers: headers, Stop: true}, nil
}

func requiredString(config map[string]any, key string) (string, error) {
	return configuredString(config, key, false)
}

func configuredString(config map[string]any, key string, allowEmpty bool) (string, error) {
	value, ok := config[key]
	if !ok {
		return "", fmt.Errorf("%s is required", key)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	if !allowEmpty {
		text = strings.TrimSpace(text)
	}
	if text == "" && !allowEmpty {
		return "", fmt.Errorf("%s is required", key)
	}
	return text, nil
}
