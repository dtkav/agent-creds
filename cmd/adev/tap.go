package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	tapConfigID       = "agent_creds_global_tap"
	tapAdminSocket    = "/run/adev-tap/admin.sock"
	tapImage          = "agent-creds-tap:dev"
	tapContainer      = "adev-tap"
	tapNetwork        = "adev-tap-metrics"
	tapNetworkNoNAT   = "com.docker.network.bridge.enable_ip_masquerade=false"
	tapDefaultUIPort  = 52000
	tapContainerLabel = "adev.tap.ui-port"
)

// GlobalTapConfig controls the one collector shared by every adev instance.
// When enabled, every newly started instance becomes a source.
type GlobalTapConfig struct {
	Enabled bool `toml:"enabled"`
	UIPort  int  `toml:"ui_port"`
}

func (c GlobalTapConfig) Port() int {
	if c.UIPort != 0 {
		return c.UIPort
	}
	return tapDefaultUIPort
}

func (c GlobalTapConfig) Validate() error {
	if c.UIPort < 0 || c.UIPort > 65535 {
		return fmt.Errorf("global tap ui_port %d is outside 0-65535", c.UIPort)
	}
	return nil
}

func agentCredsConfigDir() string {
	root := os.Getenv("XDG_CONFIG_HOME")
	if root == "" {
		home, _ := os.UserHomeDir()
		root = filepath.Join(home, ".config")
	}
	return filepath.Join(root, "agent-creds")
}

func globalTapConfigPath() string {
	return filepath.Join(agentCredsConfigDir(), "tap.toml")
}

func loadGlobalTapConfig() (GlobalTapConfig, error) {
	var config GlobalTapConfig
	if _, err := toml.DecodeFile(globalTapConfigPath(), &config); err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return config, fmt.Errorf("loading global tap config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

func applyGlobalTapConfig(config ProjectConfig) (ProjectConfig, error) {
	global, err := loadGlobalTapConfig()
	if err != nil {
		return config, err
	}
	config.TapEnabled = global.Enabled
	return config, nil
}

func saveGlobalTapConfig(config GlobalTapConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	path := globalTapConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating agent-creds config directory: %w", err)
	}
	data := []byte(fmt.Sprintf("enabled = %t\nui_port = %d\n", config.Enabled, config.Port()))
	if err := writeIfChanged(path, data, 0600); err != nil {
		return fmt.Errorf("writing global tap config: %w", err)
	}
	return os.Chmod(path, 0600)
}

func tapGlobalDir(scriptDir string) string {
	return filepath.Join(scriptDir, "generated", "tap")
}

func tapRuntimeRoot(scriptDir string) string {
	return filepath.Join(tapGlobalDir(scriptDir), "runtime")
}

func tapSourceRuntimeDir(scriptDir, slug string) string {
	return filepath.Join(tapRuntimeRoot(scriptDir), slug)
}

func tapSourcesDir(scriptDir string) string {
	return filepath.Join(tapGlobalDir(scriptDir), "sources")
}

func tapCollectorConfigDir(scriptDir string) string {
	return filepath.Join(tapGlobalDir(scriptDir), "config")
}

func tapDataDir(scriptDir string) string {
	return filepath.Join(tapGlobalDir(scriptDir), "data")
}

func legacyTapContainerName(slug string) string {
	return "adev-" + slug + "-tap"
}

func buildTapImage(scriptDir string, spinner *Spinner) error {
	spinner.Status("building global traffic tap...")
	cmd := exec.Command("docker", "build", "-q", "-t", tapImage, ".")
	cmd.Dir = filepath.Join(scriptDir, "cmd", "tap")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building traffic tap image: %w: %s", err, output)
	}
	return nil
}

type tapSource struct {
	ID       string `json:"id"`
	AdminURL string `json:"admin_url"`
	ConfigID string `json:"config_id"`
}

func prepareGlobalTapDirectories(scriptDir string) error {
	for _, dir := range []string{
		tapRuntimeRoot(scriptDir), tapSourcesDir(scriptDir),
		tapCollectorConfigDir(scriptDir), tapDataDir(scriptDir),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating global tap directory: %w", err)
		}
	}
	if err := os.Chmod(tapDataDir(scriptDir), 0700); err != nil {
		return fmt.Errorf("setting global tap data permissions: %w", err)
	}
	return nil
}

func writeTapSourcesConfig(scriptDir string) error {
	entries, err := os.ReadDir(tapSourcesDir(scriptDir))
	if err != nil {
		return err
	}
	var sources []tapSource
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tapSourcesDir(scriptDir), entry.Name()))
		if err != nil {
			return err
		}
		var source tapSource
		if err := json.Unmarshal(data, &source); err != nil {
			return fmt.Errorf("reading tap source %s: %w", entry.Name(), err)
		}
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	data, err := json.MarshalIndent(map[string]interface{}{"sources": sources}, "", "  ")
	if err != nil {
		return err
	}
	return writeIfChanged(
		filepath.Join(tapCollectorConfigDir(scriptDir), "sources.json"), data, 0600,
	)
}

func registerTapSource(scriptDir, slug string) error {
	if err := prepareGlobalTapDirectories(scriptDir); err != nil {
		return err
	}
	runtimeDir := tapSourceRuntimeDir(scriptDir, slug)
	if err := os.MkdirAll(runtimeDir, 0777); err != nil {
		return fmt.Errorf("creating tap source runtime directory: %w", err)
	}
	// Envoy drops privileges before creating its admin socket. This directory
	// contains only that socket and is separately mounted into that Envoy.
	if err := os.Chmod(runtimeDir, 0777); err != nil {
		return fmt.Errorf("setting tap source runtime permissions: %w", err)
	}
	if err := os.Remove(filepath.Join(runtimeDir, "admin.sock")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale tap socket: %w", err)
	}
	source := tapSource{
		ID:       slug,
		AdminURL: "unix:///run/adev-tap/" + slug + "/admin.sock",
		ConfigID: tapConfigID,
	}
	data, err := json.MarshalIndent(source, "", "  ")
	if err != nil {
		return err
	}
	if err := writeIfChanged(filepath.Join(tapSourcesDir(scriptDir), slug+".json"), data, 0600); err != nil {
		return err
	}
	return writeTapSourcesConfig(scriptDir)
}

func unregisterTapSource(scriptDir, slug string) error {
	if err := prepareGlobalTapDirectories(scriptDir); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(tapSourcesDir(scriptDir), slug+".json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(filepath.Join(tapSourceRuntimeDir(scriptDir, slug), "admin.sock")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := writeTapSourcesConfig(scriptDir); err != nil {
		return err
	}
	if globalTapRunning() {
		_ = run("docker", "kill", "--signal", "HUP", tapContainer)
	}
	return nil
}

func tapContainerArgs(scriptDir string, config GlobalTapConfig) []string {
	port := config.Port()
	return []string{
		"run", "-d",
		"--name", tapContainer,
		"--restart", "unless-stopped",
		"--network", tapNetwork,
		"--label", fmt.Sprintf("%s=%d", tapContainerLabel, port),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", port),
		"-v", tapRuntimeRoot(scriptDir) + ":/run/adev-tap:ro",
		"-v", tapDataDir(scriptDir) + ":/data",
		"-v", tapCollectorConfigDir(scriptDir) + ":/etc/agent-creds-tap:ro",
		"-e", "AGENT_CREDS_TAP_CONFIG=/etc/agent-creds-tap/sources.json",
		"-e", "AGENT_CREDS_TAP_DATA_DIR=/data",
		"-e", "AGENT_CREDS_TAP_LISTEN=:8080",
		tapImage,
	}
}

func ensureGlobalTapNetwork() error {
	output, err := exec.Command(
		"docker", "network", "inspect", "--format",
		"{{.Internal}} {{index .Options \"com.docker.network.bridge.enable_ip_masquerade\"}}",
		tapNetwork,
	).Output()
	if err == nil {
		if strings.TrimSpace(string(output)) != "false false" {
			return fmt.Errorf("global tap network %s exists without outbound isolation", tapNetwork)
		}
		return nil
	}
	if err := run("docker", "network", "create", "--opt", tapNetworkNoNAT, tapNetwork); err != nil {
		return fmt.Errorf("creating isolated global tap network: %w", err)
	}
	return nil
}

func globalTapRunning() bool {
	output, err := exec.Command(
		"docker", "inspect", "--format", "{{.State.Running}}", tapContainer,
	).Output()
	return err == nil && strings.TrimSpace(string(output)) == "true"
}

func globalTapHasPort(port int) bool {
	output, err := exec.Command(
		"docker", "inspect", "--format", "{{index .Config.Labels \""+tapContainerLabel+"\"}}", tapContainer,
	).Output()
	return err == nil && strings.TrimSpace(string(output)) == fmt.Sprint(port)
}

func startGlobalTapService(scriptDir string, config GlobalTapConfig, spinner *Spinner, recreate bool) error {
	if err := prepareGlobalTapDirectories(scriptDir); err != nil {
		return err
	}
	if err := writeTapSourcesConfig(scriptDir); err != nil {
		return err
	}
	if err := ensureGlobalTapNetwork(); err != nil {
		return err
	}
	if recreate || !globalTapRunning() || !globalTapHasPort(config.Port()) {
		if err := buildTapImage(scriptDir, spinner); err != nil {
			return err
		}
		run("docker", "rm", "-f", tapContainer)
		spinner.Status("starting global traffic tap...")
		if err := run("docker", tapContainerArgs(scriptDir, config)...); err != nil {
			return fmt.Errorf("starting global traffic tap: %w", err)
		}
	} else {
		if err := run("docker", "kill", "--signal", "HUP", tapContainer); err != nil {
			return fmt.Errorf("reloading global traffic tap: %w", err)
		}
	}
	return waitForGlobalTap(config.Port(), "")
}

func ensureGlobalTap(scriptDir, slug string, spinner *Spinner) (int, error) {
	config, err := loadGlobalTapConfig()
	if err != nil {
		return 0, err
	}
	if !config.Enabled {
		return 0, nil
	}
	if err := startGlobalTapService(scriptDir, config, spinner, false); err != nil {
		return 0, err
	}
	if err := waitForGlobalTap(config.Port(), slug); err != nil {
		return 0, err
	}
	return config.Port(), nil
}

func waitForGlobalTap(port int, sourceID string) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(url)
		if err == nil {
			var status struct {
				Sources map[string]bool `json:"sources"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&status)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil &&
				(sourceID == "" || status.Sources[sourceID]) {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if sourceID == "" {
		return fmt.Errorf("global traffic tap did not become healthy within 15s")
	}
	return fmt.Errorf("global traffic tap did not attach to %s within 15s", sourceID)
}
