package jsvm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vault/policy"
	"vault/provider"
)

func TestProvidersMatchAndRunInDeterministicOrder(t *testing.T) {
	directory := t.TempDir()
	writeScript(t, directory, "b.provider.js", `
registerCredentialProvider({
  name: "b",
  credentialType: "test",
  priority: 10,
  match: { hosts: ["api.*"], methods: ["GET", "POST"], paths: ["/v1/**"] },
  resolve: function (request) {
    return {
      headers: { "x-b": "yes", "x-winner": "b" },
      stop: request.path === "/v1/stop"
    };
  }
});
`)
	writeScript(t, directory, "a.provider.js", `
registerCredentialProvider({
  name: "a",
  credentialType: "test",
  priority: 10,
  match: { hosts: ["api.*"], methods: ["GET", "POST"], paths: ["/v1/**"] },
  resolve: function () {
    return { headers: { "x-a": "yes", "x-winner": "a" } };
  }
});
`)
	writeScript(t, directory, "c.provider.js", `
registerCredentialProvider({
  name: "c",
  credentialType: "test",
  priority: 20,
  match: { hosts: ["api.*"], methods: ["POST"], paths: ["/v1/**"] },
  resolve: function () {
    return { headers: { "x-c": "yes", "x-winner": "c" } };
  }
});
`)

	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name: "configured",
		Type: "test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configured := manager.Provider(Spec{Name: "configured", Type: "test"})

	getResult := resolveForTest(t, configured, provider.Request{
		Host: "api.example.com", Method: "GET", Path: "/v1/items",
	})
	if getResult.Headers["x-winner"] != "b" {
		t.Fatalf("same-priority providers did not run in filename order: %#v", getResult.Headers)
	}
	if getResult.Headers["x-a"] != "yes" || getResult.Headers["x-b"] != "yes" {
		t.Fatalf("matched providers did not merge headers: %#v", getResult.Headers)
	}

	postResult := resolveForTest(t, configured, provider.Request{
		Host: "api.example.com", Method: "POST", Path: "/v1/items",
	})
	if postResult.Headers["x-winner"] != "c" || postResult.Headers["x-c"] != "yes" {
		t.Fatalf("priority order was not applied: %#v", postResult.Headers)
	}

	stopResult := resolveForTest(t, configured, provider.Request{
		Host: "api.example.com", Method: "POST", Path: "/v1/stop",
	})
	if stopResult.Headers["x-winner"] != "b" || stopResult.Headers["x-c"] != "" {
		t.Fatalf("stop did not end the matched provider chain: %#v", stopResult.Headers)
	}

	_, err = configured.Resolve(context.Background(), provider.Request{
		Host: "other.example.com", Method: "GET", Path: "/v1/items",
	})
	if err == nil {
		t.Fatal("request outside host patterns unexpectedly matched")
	}
}

func TestReloadIsAtomicAndKeepsLastKnownGoodSet(t *testing.T) {
	directory := t.TempDir()
	scriptPath := writeScript(t, directory, "reload.provider.js", versionScript("one"))

	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name: "configured",
		Type: "reload-test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configured := manager.Provider(Spec{Name: "configured", Type: "reload-test"})
	extractor := manager.Extractor(Spec{Name: "configured", Type: "reload-test"})
	request := provider.Request{Host: "api.example.com", Method: "GET", Path: "/"}
	extractionRequest := provider.ExtractionRequest{
		Host: "api.example.com", Method: "GET", Path: "/",
		Headers: map[string]string{"x-capability": "capability"},
	}

	if got := resolveForTest(t, configured, request).Headers["x-version"]; got != "one" {
		t.Fatalf("initial version = %q, want one", got)
	}
	if got := extractForTest(t, extractor, extractionRequest); got != "capability-one" {
		t.Fatalf("initial extractor version = %q, want capability-one", got)
	}

	if err := os.WriteFile(scriptPath, []byte(versionScript("two")), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.reloadIfChanged()
	if got := resolveForTest(t, configured, request).Headers["x-version"]; got != "two" {
		t.Fatalf("reloaded version = %q, want two", got)
	}
	if got := extractForTest(t, extractor, extractionRequest); got != "capability-two" {
		t.Fatalf("reloaded extractor version = %q, want capability-two", got)
	}

	if err := os.WriteFile(scriptPath, []byte("this is not valid JavaScript {"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.reloadIfChanged()
	if got := resolveForTest(t, configured, request).Headers["x-version"]; got != "two" {
		t.Fatalf("invalid reload replaced last known-good version: %q", got)
	}
	if got := extractForTest(t, extractor, extractionRequest); got != "capability-two" {
		t.Fatalf("invalid reload replaced last known-good extractor: %q", got)
	}
}

func TestExtractorRunsInRestrictedVMWithoutCredentialConfig(t *testing.T) {
	directory := t.TempDir()
	writeScript(t, directory, "zones.provider.js", `
registerCredentialExtractor({
  name: "zones-extractor",
  credentialType: "zones-test",
  extract: function (request) {
    return [
      String(arguments.length),
      typeof arguments[1],
      typeof request.value,
      typeof $http,
      typeof $exec,
      typeof $jwt
    ].join(":");
  }
});
registerCredentialProvider({
  name: "zones-provider",
  credentialType: "zones-test",
  resolve: function (_request, config) {
    return {headers: {authorization: config.value}};
  }
});
`)
	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name:   "configured",
		Type:   "zones-test",
		Config: map[string]any{"value": "resolved-secret"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	extracted := extractForTest(t, manager.Extractor(Spec{
		Name:   "configured",
		Type:   "zones-test",
		Config: map[string]any{"value": "must-not-enter-extractor"},
	}), provider.ExtractionRequest{})
	if extracted != "1:undefined:undefined:undefined:undefined:undefined" {
		t.Fatalf("extractor boundary = %q", extracted)
	}

	resolved := resolveForTest(t, manager.Provider(Spec{
		Name:   "configured",
		Type:   "zones-test",
		Config: map[string]any{"value": "resolved-secret"},
	}), provider.Request{})
	if got := resolved.Headers["authorization"]; got != "resolved-secret" {
		t.Fatalf("provider did not receive resolved config: %q", got)
	}
}

func TestProviderRuntimeEncodesBase64(t *testing.T) {
	providerDirectory := t.TempDir()
	writeScript(t, providerDirectory, "base64.provider.js", `
registerCredentialProvider({
  name: "base64-test",
  credentialType: "base64-test",
  match: { hosts: ["api.example.com"] },
  resolve: function (_request, config) {
    return { headers: { authorization: "Basic " + $base64.encode(config.value) } };
  }
});
`)
	spec := Spec{
		Name: "configured",
		Type: "base64-test",
		Config: map[string]any{
			"value": "user:password",
		},
	}
	manager, err := NewManager([]string{providerDirectory}, 1, []Spec{spec})
	if err != nil {
		t.Fatal(err)
	}
	result := resolveForTest(t, manager.Provider(spec), provider.Request{
		Host: "api.example.com", Method: "GET", Path: "/v1/resource",
	})
	wantAuthorization := "Basic dXNlcjpwYXNzd29yZA=="
	if got := result.Headers["authorization"]; got != wantAuthorization {
		t.Fatalf("base64 injection = %q, want %q", got, wantAuthorization)
	}
}

func TestConfiguredTypeMustBeRegistered(t *testing.T) {
	_, err := NewManager([]string{t.TempDir()}, 1, []Spec{{
		Name: "configured",
		Type: "missing",
	}})
	if err == nil {
		t.Fatal("unregistered configured provider type was accepted")
	}
}

func TestLocalProviderScriptsLoadWhenPresent(t *testing.T) {
	providerDirectory := filepath.Join("..", "..", "providers.d")
	files, _, err := scanScripts([]string{providerDirectory})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no local deployment provider scripts")
	}
	if _, err := newScriptRuntime(files); err != nil {
		t.Fatalf("loading local provider scripts: %v", err)
	}
}

func TestProviderExecutionHonorsContextCancellation(t *testing.T) {
	directory := t.TempDir()
	writeScript(t, directory, "blocking.provider.js", `
registerCredentialProvider({
  name: "blocking",
  credentialType: "blocking-test",
  resolve: function () {
    while (true) {}
  }
});
`)
	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name: "configured",
		Type: "blocking-test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configured := manager.Provider(Spec{Name: "configured", Type: "blocking-test"})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := configured.Resolve(ctx, provider.Request{}); err == nil {
		t.Fatal("blocking provider ignored context cancellation")
	}
}

func TestHTTPHelperUsesProviderContext(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("x-provider-test"); got != "yes" {
			t.Errorf("x-provider-test = %q, want yes", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if got := string(body); got != `{"identity":"agent"}` {
			t.Errorf("body = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"x-test-response": []string{"ok"}},
			Body:       io.NopCloser(strings.NewReader(`{"token":"session-token"}`)),
			Request:    r,
		}, nil
	})

	directory := t.TempDir()
	writeScript(t, directory, "http.provider.js", `
registerCredentialProvider({
  name: "http",
  credentialType: "http-test",
  resolve: function (_request, config) {
    var response = $http.request({
      method: "POST",
      url: config.url,
      headers: {
        "content-type": "application/json",
        "x-provider-test": "yes"
      },
      body: JSON.stringify({identity: "agent"})
    });
    if (response.status !== 200) {
      throw new Error("unexpected status " + response.status);
    }
    if (response.headers["x-test-response"][0] !== "ok") {
      throw new Error("missing response header");
    }
    return {
      headers: {
        authorization: JSON.parse(response.body).token
      }
    };
  }
});
`)
	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name:   "configured",
		Type:   "http-test",
		Config: map[string]any{"url": "https://session.example.test/login"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	set := manager.current.Load()
	runtime := <-set.pool
	runtime.httpClient = &http.Client{Transport: transport}
	set.pool <- runtime
	configured := manager.Provider(Spec{
		Name:   "configured",
		Type:   "http-test",
		Config: map[string]any{"url": "https://session.example.test/login"},
	})
	result := resolveForTest(t, configured, provider.Request{})
	if got := result.Headers["authorization"]; got != "session-token" {
		t.Fatalf("authorization = %q, want session-token", got)
	}
}

func TestExecRunCanReplaceInheritedEnvironment(t *testing.T) {
	t.Setenv("AGENT_CREDS_EXEC_PARENT", "must-not-leak")
	directory := t.TempDir()
	writeScript(t, directory, "exec.provider.js", fmt.Sprintf(`
registerCredentialProvider({
  name: "exec",
  credentialType: "exec-test",
  resolve: function () {
    var output = $exec.run(%q, ["-test.run=TestExecRunHelperProcess", "--"], {
      inheritEnv: false,
      env: {
        AGENT_CREDS_EXEC_HELPER: "1",
        AGENT_CREDS_EXEC_EXPLICIT: "available"
      }
    });
    return { headers: { "x-exec-output": output } };
  }
});
`, os.Args[0]))

	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name: "configured",
		Type: "exec-test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configured := manager.Provider(Spec{Name: "configured", Type: "exec-test"})
	got := resolveForTest(t, configured, provider.Request{}).Headers["x-exec-output"]
	if got != "explicit=available;parent=" {
		t.Fatalf("isolated child environment = %q", got)
	}
}

func TestExecRunInheritsEnvironmentByDefault(t *testing.T) {
	t.Setenv("AGENT_CREDS_EXEC_HELPER", "1")
	t.Setenv("AGENT_CREDS_EXEC_PARENT", "inherited")
	directory := t.TempDir()
	writeScript(t, directory, "exec.provider.js", fmt.Sprintf(`
registerCredentialProvider({
  name: "exec",
  credentialType: "exec-test",
  resolve: function () {
    var output = $exec.run(%q, ["-test.run=TestExecRunHelperProcess", "--"]);
    return { headers: { "x-exec-output": output } };
  }
});
`, os.Args[0]))

	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name: "configured",
		Type: "exec-test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configured := manager.Provider(Spec{Name: "configured", Type: "exec-test"})
	got := resolveForTest(t, configured, provider.Request{}).Headers["x-exec-output"]
	if got != "explicit=;parent=inherited" {
		t.Fatalf("default child environment = %q", got)
	}
}

func TestExecRunHelperProcess(t *testing.T) {
	if os.Getenv("AGENT_CREDS_EXEC_HELPER") != "1" {
		return
	}
	fmt.Printf("explicit=%s;parent=%s", os.Getenv("AGENT_CREDS_EXEC_EXPLICIT"), os.Getenv("AGENT_CREDS_EXEC_PARENT"))
	os.Exit(0)
}

func TestUpstreamPolicyReceivesVerifiedContextAndEveryConstraint(t *testing.T) {
	directory := t.TempDir()
	writeScript(t, directory, "service.policy.js", `
registerUpstreamPolicy({
  name: "service-policy",
  policyType: "example-service",
  validate: function (config) {
    if (config.service !== "records") throw new Error("service is required");
  },
  authorize: function (request, config) {
    if (request.subject !== "customer-123") {
      return {allow: false, reason: "wrong subject"};
    }
    for (var i = 0; i < request.constraints.length; i++) {
      var caveat = request.constraints[i];
      if (caveat.namespace !== "example") {
        return {allow: false, reason: "unknown namespace"};
      }
      if (caveat.body.service.indexOf(config.service) === -1) {
        return {allow: false, reason: "service excluded"};
      }
    }
    return true;
  }
});
`)
	manager, err := NewManagerWithPolicies(
		[]string{directory},
		1,
		nil,
		[]PolicySpec{{
			Name:   "records",
			Type:   "example-service",
			Config: map[string]any{"service": "records"},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := manager.Policy(PolicySpec{
		Name:   "records",
		Type:   "example-service",
		Config: map[string]any{"service": "records"},
	})
	subject := "customer-123"
	request := policy.Request{
		Host:    "records.example.test",
		Method:  "GET",
		Path:    "/v1/records/1",
		Subject: &subject,
		Constraints: []policy.Constraint{
			{Namespace: "example", Body: map[string]any{"service": []string{"records", "files"}}},
			{Namespace: "example", Body: map[string]any{"service": []string{"records"}}},
		},
	}
	decision, err := authorizer.Authorize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow {
		t.Fatalf("allowed request denied: %s", decision.Reason)
	}

	request.Constraints = append(request.Constraints, policy.Constraint{
		Namespace: "example",
		Body:      map[string]any{"service": []string{"files"}},
	})
	decision, err = authorizer.Authorize(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.Reason != "service excluded" {
		t.Fatalf("attenuating constraint did not narrow access: %#v", decision)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestCachingRequiresExplicitCredentialScope(t *testing.T) {
	directory := t.TempDir()
	scriptPath := writeScript(t, directory, "cache.provider.js", `
var calls = 0;
registerCredentialProvider({
  name: "cache",
  credentialType: "cache-test",
  resolve: function () {
    calls++;
    return {
      headers: { "x-calls": String(calls) },
      expiresAt: 4102444800
    };
  }
});
`)
	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name: "configured",
		Type: "cache-test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configured := manager.Provider(Spec{Name: "configured", Type: "cache-test"})

	if got := resolveForTest(t, configured, provider.Request{Path: "/one"}).Headers["x-calls"]; got != "1" {
		t.Fatalf("first uncached call = %q, want 1", got)
	}
	if got := resolveForTest(t, configured, provider.Request{Path: "/two"}).Headers["x-calls"]; got != "2" {
		t.Fatalf("expiresAt implicitly cached a request-dependent result: call = %q", got)
	}

	if err := os.WriteFile(scriptPath, []byte(`
var calls = 0;
registerCredentialProvider({
  name: "cache",
  credentialType: "cache-test",
  cache: "credential",
  resolve: function () {
    calls++;
    return {
      headers: { "x-calls": String(calls) },
      expiresAt: 4102444800
    };
  }
});
`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.reloadIfChanged()

	if got := resolveForTest(t, configured, provider.Request{Path: "/one"}).Headers["x-calls"]; got != "1" {
		t.Fatalf("first credential-cached call = %q, want 1", got)
	}
	if got := resolveForTest(t, configured, provider.Request{Path: "/two"}).Headers["x-calls"]; got != "1" {
		t.Fatalf("credential-scoped result was not reused: call = %q", got)
	}
}

func TestCredentialCacheIncludesMatchedHandlerSet(t *testing.T) {
	directory := t.TempDir()
	writeScript(t, directory, "cache-patterns.provider.js", `
registerCredentialProvider({
  name: "a",
  credentialType: "cache-pattern-test",
  cache: "credential",
  match: { paths: ["/a"] },
  resolve: function () {
    return { headers: { "x-provider": "a" }, expiresAt: 4102444800 };
  }
});
registerCredentialProvider({
  name: "b",
  credentialType: "cache-pattern-test",
  cache: "credential",
  match: { paths: ["/b"] },
  resolve: function () {
    return { headers: { "x-provider": "b" }, expiresAt: 4102444800 };
  }
});
`)
	manager, err := NewManager([]string{directory}, 1, []Spec{{
		Name: "configured",
		Type: "cache-pattern-test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	configured := manager.Provider(Spec{Name: "configured", Type: "cache-pattern-test"})

	if got := resolveForTest(t, configured, provider.Request{Path: "/a"}).Headers["x-provider"]; got != "a" {
		t.Fatalf("/a provider = %q, want a", got)
	}
	if got := resolveForTest(t, configured, provider.Request{Path: "/b"}).Headers["x-provider"]; got != "b" {
		t.Fatalf("/b reused the wrong matched-chain cache entry: %q", got)
	}
}

func resolveForTest(t *testing.T, configured provider.CredentialProvider, request provider.Request) provider.Result {
	t.Helper()
	result, err := configured.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func extractForTest(t *testing.T, extractor provider.CredentialExtractor, request provider.ExtractionRequest) string {
	t.Helper()
	token, err := extractor.Extract(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func writeScript(t *testing.T, directory, name, source string) string {
	t.Helper()
	scriptPath := filepath.Join(directory, name)
	if err := os.WriteFile(scriptPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return scriptPath
}

func versionScript(version string) string {
	return `
registerCredentialExtractor({
  name: "reload-extractor",
  credentialType: "reload-test",
  extract: function (request) {
    return request.headers["x-capability"] + "-` + version + `";
  }
});
registerCredentialProvider({
  name: "reload",
  credentialType: "reload-test",
  resolve: function () {
    return { headers: { "x-version": "` + version + `" } };
  }
});
`
}
