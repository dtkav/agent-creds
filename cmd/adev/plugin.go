package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// discoverTOMLFiles finds all TOML files in the given directories.
// Returns a map of name -> file path, with later sources overriding earlier ones.
func discoverTOMLFiles(dirs []string) map[string]string {
	result := make(map[string]string)
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".toml") {
				continue
			}
			baseName := strings.TrimSuffix(name, ".toml")
			result[baseName] = filepath.Join(dir, name)
		}
	}
	return result
}

// DiscoverPlugins finds all plugin files from bundled, global, and project directories.
// Returns a map of plugin name -> file path, with later sources overriding earlier ones.
func DiscoverPlugins(projectDir, scriptDir string) map[string]string {
	dirs := []string{
		filepath.Join(scriptDir, "plugins"),         // bundled
		expandPath("~/.config/agent-creds/plugins"), // global
		filepath.Join(projectDir, "plugins"),        // project
	}
	return discoverTOMLFiles(dirs)
}

// DiscoverAgents finds all agent files from bundled, global, and project directories.
// Returns a map of agent name -> file path, with later sources overriding earlier ones.
func DiscoverAgents(projectDir, scriptDir string) map[string]string {
	dirs := []string{
		filepath.Join(scriptDir, "agents"),         // bundled
		expandPath("~/.config/agent-creds/agents"), // global
		filepath.Join(projectDir, "agents"),        // project
	}
	return discoverTOMLFiles(dirs)
}

// LoadPlugin parses a plugin TOML file.
func LoadPlugin(path string) (PluginConfig, error) {
	var plugin PluginConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return plugin, err
	}
	if err := toml.Unmarshal(data, &plugin); err != nil {
		return plugin, err
	}
	return plugin, nil
}

// LoadAgent parses an agent TOML file.
func LoadAgent(path string) (AgentConfig, error) {
	var agent AgentConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return agent, err
	}
	if err := toml.Unmarshal(data, &agent); err != nil {
		return agent, err
	}
	return agent, nil
}

// FilterPlugins returns the list of plugins to enable based on config settings.
// If explicit plugins list is set, only those are enabled.
// Otherwise, all discovered plugins are enabled except those in disabled list.
func FilterPlugins(discovered map[string]string, enabled, disabled []string) []string {
	var result []string

	if len(enabled) > 0 {
		// Explicit list: check for "*" (all) or specific names
		if len(enabled) == 1 && enabled[0] == "*" {
			// Enable all discovered plugins
			for name := range discovered {
				if !sliceContains(disabled, name) {
					result = append(result, name)
				}
			}
		} else {
			// Enable only specified plugins
			for _, name := range enabled {
				if _, ok := discovered[name]; ok {
					if !sliceContains(disabled, name) {
						result = append(result, name)
					}
				}
			}
		}
	} else {
		// Default: enable all discovered plugins
		for name := range discovered {
			if !sliceContains(disabled, name) {
				result = append(result, name)
			}
		}
	}

	return result
}

// MergePlugins loads and merges enabled plugins into the project config.
func MergePlugins(cfg *ProjectConfig, discovered map[string]string, enabled []string, projectDir string) error {
	for _, name := range enabled {
		path, ok := discovered[name]
		if !ok {
			continue
		}

		plugin, err := LoadPlugin(path)
		if err != nil {
			return fmt.Errorf("loading plugin %s: %w", name, err)
		}

		// Append packages
		cfg.Packages = append(cfg.Packages, plugin.Packages...)

		// Collect inline nix
		if nix := strings.TrimSpace(plugin.Nix); nix != "" {
			cfg.NixExprs = append(cfg.NixExprs, nix)
		}

		// Merge upstream
		if cfg.Upstream == nil {
			cfg.Upstream = make(map[string]UpstreamConfig)
		}
		for host, upstream := range plugin.Upstream {
			if _, exists := cfg.Upstream[host]; !exists {
				cfg.Upstream[host] = upstream
			}
		}

		// Append browser targets
		cfg.BrowserTargets = append(cfg.BrowserTargets, plugin.BrowserTargets...)

		// Append CDP targets
		cfg.CDPTargets = append(cfg.CDPTargets, plugin.CDPTargets...)

		// Append mounts with path expansion
		for _, mount := range plugin.Mounts {
			expandedMount := MountConfig{
				Source:   expandMountPath(mount.Source, projectDir),
				Target:   mount.Target,
				Readonly: mount.Readonly,
			}
			cfg.Mounts = append(cfg.Mounts, expandedMount)
		}

		// Append env
		cfg.Env = append(cfg.Env, plugin.Env...)
	}

	return nil
}

// MergeAgent merges an agent's config into the project config.
func MergeAgent(cfg *ProjectConfig, agent AgentConfig, projectDir string) {
	// Set entrypoint
	if agent.Entrypoint != "" {
		cfg.Entrypoint = agent.Entrypoint
	}

	// Append packages
	cfg.Packages = append(cfg.Packages, agent.Packages...)

	// Collect inline nix
	if nix := strings.TrimSpace(agent.Nix); nix != "" {
		cfg.NixExprs = append(cfg.NixExprs, nix)
	}

	// Merge upstream
	if cfg.Upstream == nil {
		cfg.Upstream = make(map[string]UpstreamConfig)
	}
	for host, upstream := range agent.Upstream {
		if _, exists := cfg.Upstream[host]; !exists {
			cfg.Upstream[host] = upstream
		}
	}

	// Append browser targets
	cfg.BrowserTargets = append(cfg.BrowserTargets, agent.BrowserTargets...)

	// Append CDP targets
	cfg.CDPTargets = append(cfg.CDPTargets, agent.CDPTargets...)

	// Append mounts with path expansion
	for _, mount := range agent.Mounts {
		expandedMount := MountConfig{
			Source:   expandMountPath(mount.Source, projectDir),
			Target:   mount.Target,
			Readonly: mount.Readonly,
		}
		cfg.Mounts = append(cfg.Mounts, expandedMount)
	}

	// Append env
	cfg.Env = append(cfg.Env, agent.Env...)
}

// expandPath expands ~ to home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

// expandMountPath expands ~ and ./ in mount source paths.
func expandMountPath(path, projectDir string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	if strings.HasPrefix(path, "./") {
		return filepath.Join(projectDir, path[2:])
	}
	return path
}

// sliceContains checks if a string slice contains a value.
func sliceContains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// resolveEnvValue resolves an environment variable value.
// Supports "from-file:path" syntax to read value from a file.
func resolveEnvValue(value string) string {
	const prefix = "from-file:"
	if strings.HasPrefix(value, prefix) {
		path := expandPath(strings.TrimPrefix(value, prefix))
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not read env file %s: %v\n", path, err)
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	return value
}
