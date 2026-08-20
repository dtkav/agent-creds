package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGlobalTapUIPort(t *testing.T) {
	if got := (GlobalTapConfig{}).Port(); got != tapDefaultUIPort {
		t.Fatalf("default global tap port = %d", got)
	}
	if got := (GlobalTapConfig{UIPort: 54321}).Port(); got != 54321 {
		t.Fatalf("configured global tap port = %d", got)
	}
}

func TestRegisterTapSourceWaitsForReadyAdminSocket(t *testing.T) {
	scriptDir, err := os.MkdirTemp("/tmp", "tap-source-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(scriptDir) })
	const slug = "ready-agent"
	if err := prepareTapSourceRuntime(scriptDir, slug); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(tapSourceRuntimeDir(scriptDir, slug), "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := registerTapSource(scriptDir, t.TempDir(), slug); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(tapCollectorConfigDir(scriptDir), "sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), slug) || !strings.Contains(string(data), `"agent_id": "ready-agent"`) {
		t.Fatalf("ready source was not registered: %s", data)
	}
}

func TestTapFilterPrecedesCredentialInjection(t *testing.T) {
	g := &Generator{cfg: ProjectConfig{TapEnabled: true}}
	filters := g.httpFilters()
	if len(filters) != 3 || filters[0]["name"] != "envoy.filters.http.tap" || filters[1]["name"] != "envoy.filters.http.ext_authz" {
		t.Fatalf("unexpected HTTP filters: %#v", filters)
	}
}

func TestTapAuthAccessLogContainsOnlyStatusMetadata(t *testing.T) {
	g := &Generator{cfg: ProjectConfig{TapEnabled: true}}
	logs := g.accessLogConfig()
	if len(logs) != 3 {
		t.Fatalf("tap access log count = %d, want 3", len(logs))
	}
	authLog := logs[2]
	typed, ok := authLog["typed_config"].(map[string]interface{})
	if !ok || typed["path"] != "/run/adev-tap/auth.log" {
		t.Fatalf("unexpected auth access log: %#v", authLog)
	}
	encoded, err := json.Marshal(authLog)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, want := range []string{
		"platform.claude.com", "/v1/oauth/token", "%RESPONSE_CODE%",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("auth access log is missing %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{
		"%REQ(", "%RESP(", "authorization", "request_body", "response_body",
	} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("auth access log contains forbidden material %q: %s", forbidden, text)
		}
	}
}

func TestTapDisabledOmitsAuthAccessLog(t *testing.T) {
	if logs := (&Generator{}).accessLogConfig(); len(logs) != 2 {
		t.Fatalf("disabled tap access log count = %d, want 2", len(logs))
	}
}

func TestTapDisabledByDefault(t *testing.T) {
	for _, filter := range (&Generator{}).httpFilters() {
		if filter["name"] == "envoy.filters.http.tap" {
			t.Fatal("tap filter enabled by default")
		}
	}
}

func TestTapOmittedFromOuterConnectTunnel(t *testing.T) {
	g := &Generator{cfg: ProjectConfig{TapEnabled: true}}
	filterChain := g.connectFilterChain(nil)
	hcm := filterChain["filters"].([]map[string]interface{})[0]["typed_config"].(map[string]interface{})
	for _, filter := range hcm["http_filters"].([]map[string]interface{}) {
		if filter["name"] == "envoy.filters.http.tap" {
			t.Fatal("outer CONNECT tunnel includes tap filter")
		}
	}
}

func TestTapAddsPrivateEnvoyAdminSocket(t *testing.T) {
	root := t.TempDir()
	genDir := filepath.Join(root, "generated", "instances", "test")
	g, err := NewGenerator(root, genDir, ProjectConfig{TapEnabled: true, Upstream: map[string]UpstreamConfig{"api.example.com": {}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.generateEnvoyJSON(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(genDir, "envoy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	pipe := config["admin"].(map[string]interface{})["address"].(map[string]interface{})["pipe"].(map[string]interface{})
	if pipe["path"] != tapAdminSocket {
		t.Fatalf("tap admin socket = %v", pipe["path"])
	}
}

func TestRegisterTapSourcesWritesGlobalFanInConfig(t *testing.T) {
	scriptDir := t.TempDir()
	if err := prepareTapSourceRuntime(scriptDir, "staging-agent"); err != nil {
		t.Fatal(err)
	}
	if err := writeTapSourceRegistration(scriptDir, "", "staging-agent"); err != nil {
		t.Fatal(err)
	}
	if err := prepareTapSourceRuntime(scriptDir, "review-agent"); err != nil {
		t.Fatal(err)
	}
	if err := writeTapSourceRegistration(scriptDir, "", "review-agent"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(tapCollectorConfigDir(scriptDir), "sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"id": "staging-agent"`, `"id": "review-agent"`,
		`"agent_id": "staging-agent"`, `"agent_id": "review-agent"`,
		"unix:///run/adev-tap/staging-agent/admin.sock",
		"unix:///run/adev-tap/review-agent/admin.sock",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("global source config missing %q: %s", want, data)
		}
	}
	if strings.Index(string(data), "review-agent") > strings.Index(string(data), "staging-agent") {
		t.Fatalf("unexpected tap source config: %s", data)
	}
	info, err := os.Stat(tapDataDir(scriptDir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("tap data permissions = %o", info.Mode().Perm())
	}
	if err := unregisterTapSource(scriptDir, "review-agent"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(tapCollectorConfigDir(scriptDir), "sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "review-agent") || !strings.Contains(string(data), "staging-agent") {
		t.Fatalf("source unregister damaged fan-in config: %s", data)
	}
}

func TestTapSourceConfigResolvesAgentIDAndName(t *testing.T) {
	scriptDir := t.TempDir()
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)
	if err := prepareGlobalTapDirectories(scriptDir); err != nil {
		t.Fatal(err)
	}
	const slug = "mq-0m62fua8t3xk2sl-codex-identity-v2"
	identityRoot := filepath.Join(scriptDir, "identity-root")
	if err := os.MkdirAll(filepath.Join(identityRoot, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(identityRoot, ".claude", "identities.json"),
		[]byte(`{"0m62fua8t3xk2sl":{"name":"Dispatch"}}`), 0600,
	); err != nil {
		t.Fatal(err)
	}
	manifestDir := filepath.Join(
		cacheDir, "merge-queue", "watchd", "codex", "0m62fua8t3xk2sl")
	if err := os.MkdirAll(manifestDir, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"mounts":[{"source":%q}]}`, identityRoot)
	if err := os.WriteFile(
		filepath.Join(manifestDir, "sandbox-manifest.json"), []byte(manifest), 0600,
	); err != nil {
		t.Fatal(err)
	}
	legacy := tapSource{
		ID: slug, AdminURL: "unix:///run/adev-tap/" + slug + "/admin.sock", ConfigID: tapConfigID,
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tapSourcesDir(scriptDir), slug+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeTapSourcesConfig(scriptDir); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(tapCollectorConfigDir(scriptDir), "sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"agent_id": "0m62fua8t3xk2sl"`) ||
		!strings.Contains(string(data), `"agent_name": "Dispatch"`) {
		t.Fatalf("source identity was not resolved: %s", data)
	}
}

func TestTapSourceAgentID(t *testing.T) {
	for input, want := range map[string]string{
		"mq-0m62fua8t3xk2sl-codex-identity-v2": "0m62fua8t3xk2sl",
		"ordinary-sandbox":                     "ordinary-sandbox",
		"mq-malformed":                         "mq-malformed",
	} {
		if got := tapSourceAgentID(input); got != want {
			t.Errorf("tapSourceAgentID(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTapContainerIsHardenedAndGlobal(t *testing.T) {
	args := tapContainerArgs("/repo", GlobalTapConfig{})
	uiBinding := fmt.Sprintf("127.0.0.1:%d:8080", tapDefaultUIPort)
	for _, want := range []string{"--cap-drop", "ALL", "no-new-privileges", "--read-only", tapNetwork, uiBinding, tapContainer, tapImage} {
		if !slices.Contains(args, want) {
			t.Fatalf("tap args missing %q: %q", want, args)
		}
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "vault") || strings.Contains(joined, "macaroon") {
		t.Fatalf("tap args expose credential-plane material: %s", joined)
	}
	if strings.Contains(joined, "adev-staging") || strings.Contains(joined, "generated/instances") {
		t.Fatalf("global tap is instance-scoped: %s", joined)
	}
}

func TestGlobalTapConfigRejectsInvalidUIPort(t *testing.T) {
	for _, port := range []int{-1, 70000} {
		if err := (GlobalTapConfig{UIPort: port}).Validate(); err == nil {
			t.Fatalf("invalid tap UI port %d was accepted", port)
		}
	}
}

func TestGlobalTapConfigControlsEveryInstance(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	project := ProjectConfig{}
	effective, err := applyGlobalTapConfig(project)
	if err != nil {
		t.Fatal(err)
	}
	if effective.TapEnabled {
		t.Fatal("instance tap enabled while global service is disabled")
	}
	if err := saveGlobalTapConfig(GlobalTapConfig{Enabled: true, UIPort: 53123}); err != nil {
		t.Fatal(err)
	}
	effective, err = applyGlobalTapConfig(project)
	if err != nil {
		t.Fatal(err)
	}
	if !effective.TapEnabled {
		t.Fatal("globally enabled instance was not registered")
	}
	if globalTapConfigPath() != filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "agent-creds", "tap.toml") {
		t.Fatalf("global config path = %s", globalTapConfigPath())
	}
}

func TestProjectCannotOverrideGlobalTap(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	projectDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(projectDir, "agent-creds.toml"),
		[]byte("[tap]\nenabled = false\n"), 0600,
	); err != nil {
		t.Fatal(err)
	}
	project, err := LoadProjectConfig(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveGlobalTapConfig(GlobalTapConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	effective, err := applyGlobalTapConfig(project)
	if err != nil {
		t.Fatal(err)
	}
	if !effective.TapEnabled {
		t.Fatal("project-local tap setting overrode the global switch")
	}
}
