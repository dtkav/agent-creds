package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testSkillRef = "0123456789abcdef0123456789abcdef01234567"

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}

func skillRegistration(name, repo, path, nix string) string {
	registration := "name = \"" + name + "\"\n" +
		"repo = \"" + repo + "\"\n" +
		"ref = \"" + testSkillRef + "\"\n"
	if path != "" {
		registration += "path = \"" + path + "\"\n"
	}
	if nix != "" {
		registration += "nix = \"" + nix + "\"\n"
	}
	return registration
}

func TestLoadProjectConfigResolvesNamedSkillsFromAgentPluginAndSandbox(t *testing.T) {
	root := t.TempDir()
	scriptDir := filepath.Join(root, "agent-creds")
	projectDir := filepath.Join(root, "project")

	writeTestFile(t, filepath.Join(projectDir, "sandbox.toml"), `
[sandbox]
agent = "test-agent"
skills = ["sandbox-skill"]
`)
	writeTestFile(t, filepath.Join(scriptDir, "agents", "test-agent.toml"), `
name = "test-agent"
skill_dir = ".agent/skills"
plugins = ["observability"]
skills = ["agent-skill"]
`)
	writeTestFile(t, filepath.Join(scriptDir, "plugins", "observability.toml"), `
name = "observability"
skills = ["plugin-skill"]
`)

	for _, name := range []string{"sandbox-skill", "agent-skill", "plugin-skill"} {
		writeTestFile(t, filepath.Join(scriptDir, "skills", name+".toml"),
			skillRegistration(name, "https://example.com/shared/skills.git", "skills/"+name, ""))
	}
	// Project scope overrides the bundled registration by name.
	writeTestFile(t, filepath.Join(projectDir, "skills", "plugin-skill.toml"),
		skillRegistration("plugin-skill", "https://example.com/project/skills.git", "plugin", "[ pkgs.jq ]"))

	cfg, err := LoadProjectConfigWithPlugins(projectDir, scriptDir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SkillDir != ".agent/skills" {
		t.Fatalf("skill dir = %q", cfg.SkillDir)
	}
	if len(cfg.Skills) != 3 {
		t.Fatalf("resolved skills = %#v", cfg.Skills)
	}
	if got := cfg.Skills["plugin-skill"].Repo; got != "https://example.com/project/skills.git" {
		t.Fatalf("project registration did not override bundled registration: %q", got)
	}
	if !strings.Contains(renderPackagesNix(cfg), "[ pkgs.jq ]") {
		t.Fatal("selected skill's optional Nix packages were not merged")
	}
}

func TestSkillRegistrationRequiresLiteralURLAndRef(t *testing.T) {
	for _, test := range []struct {
		name  string
		skill SkillConfig
		want  string
	}{
		{
			name:  "Nix shorthand is not a Git URL",
			skill: SkillConfig{Name: "metrics", Repo: "github:org/repo", Ref: testSkillRef},
			want:  "unsupported URL scheme",
		},
		{
			name:  "ref is required",
			skill: SkillConfig{Name: "metrics", Repo: "https://github.com/org/repo.git"},
			want:  "non-empty Git ref",
		},
		{
			name:  "parent path escapes repository",
			skill: SkillConfig{Name: "metrics", Repo: "https://github.com/org/repo.git", Ref: testSkillRef, Path: "../metrics"},
			want:  "clean relative directory",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.skill.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRenderSkillsNixUsesRepoRefPathAndNeutralLayout(t *testing.T) {
	cfg := ProjectConfig{
		SkillDir: ".claude/skills",
		Skills: map[string]SkillConfig{
			"log-query": {
				Name: "log-query",
				Repo: "https://github.com/example/capabilities.git",
				Ref:  testSkillRef,
				Path: "skills/log-query",
			},
		},
	}
	got := renderSkillsNix(cfg)
	for _, want := range []string{
		`builtins.fetchGit { url = "https://github.com/example/capabilities.git"; rev = "` + testSkillRef + `"; }`,
		`/skills/log-query/.`,
		`$out/skills/log-query/SKILL.md`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated skills.nix is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, ".claude") {
		t.Fatalf("provider-neutral skills layer contains harness layout:\n%s", got)
	}

	if nix, err := exec.LookPath("nix-instantiate"); err == nil {
		path := filepath.Join(t.TempDir(), "skills.nix")
		writeTestFile(t, path, got)
		if out, err := exec.Command(nix, "--parse", path).CombinedOutput(); err != nil {
			t.Fatalf("generated skills.nix does not parse: %v\n%s\n%s", err, out, got)
		}
	}
}

func TestRenderSkillsNixKeepsSymbolicGitRef(t *testing.T) {
	cfg := ProjectConfig{Skills: map[string]SkillConfig{
		"metrics": {
			Name: "metrics",
			Repo: "https://github.com/example/capabilities.git",
			Ref:  "release/v2",
		},
	}}
	got := renderSkillsNix(cfg)
	if want := `ref = "release/v2"`; !strings.Contains(got, want) {
		t.Fatalf("generated skills.nix is missing %q:\n%s", want, got)
	}
}

func TestSkillRefAndHarnessLayoutChangeEnvironmentKey(t *testing.T) {
	scriptDir := t.TempDir()
	writeTestFile(t, filepath.Join(scriptDir, "flake.nix"), "{}\n")
	cfg := ProjectConfig{
		Sandbox:  SandboxConfig{Agent: "codex"},
		SkillDir: ".codex/skills",
		Skills: map[string]SkillConfig{
			"metrics": {
				Name: "metrics",
				Repo: "https://github.com/example/capabilities.git",
				Ref:  "main",
			},
		},
	}
	base := envHash(cfg, scriptDir)

	updatedRef := cfg
	updatedRef.Skills = map[string]SkillConfig{
		"metrics": {
			Name: "metrics",
			Repo: "https://github.com/example/capabilities.git",
			Ref:  "release/v2",
		},
	}
	if got := envHash(updatedRef, scriptDir); got == base {
		t.Fatal("changing a skill ref did not change the environment cache key")
	}

	updatedLayout := cfg
	updatedLayout.SkillDir = ".claude/skills"
	if got := envHash(updatedLayout, scriptDir); got == base {
		t.Fatal("changing the harness skill directory did not change the environment cache key")
	}
}

func TestRenderHarnessNixCopiesNeutralSkillsIntoHarnessLayout(t *testing.T) {
	cfg := ProjectConfig{
		SkillDir: ".claude/skills",
		Skills: map[string]SkillConfig{
			"log-query": {Name: "log-query"},
		},
	}
	got := renderHarnessNix(cfg)
	for _, want := range []string{
		`${skills}/skills/log-query/.`,
		`$out/home/.claude/skills/log-query/SKILL.md`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated harness.nix is missing %q:\n%s", want, got)
		}
	}
	if nix, err := exec.LookPath("nix-instantiate"); err == nil {
		path := filepath.Join(t.TempDir(), "harness.nix")
		writeTestFile(t, path, got)
		if out, err := exec.Command(nix, "--parse", path).CombinedOutput(); err != nil {
			t.Fatalf("generated harness.nix does not parse: %v\n%s\n%s", err, out, got)
		}
	}
}

func TestPrepareSkillMountsOverlaysPersistentAgentState(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	root := t.TempDir()
	scriptDir := filepath.Join(root, "agent-creds")
	instanceDir := filepath.Join(scriptDir, "generated", "instances", "test")
	envPath := "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-sandbox-env"
	key := "0123456789abcdef"
	privateRoot := filepath.Join(configHome, "agent-creds", "nix", "envs", key)
	store := filepath.Join(privateRoot, "nix", "store")
	writeTestFile(t, filepath.Join(store, filepath.Base(envPath), "placeholder"), "")
	writeTestFile(t, sandboxEnvStoreFile(envPath), key+"\n")
	writeTestFile(t, filepath.Join(privateRoot, "harness-layer", ".codex", "skills", "metrics", "SKILL.md"), "---\nname: metrics\n---\n")

	cfg := ProjectConfig{
		Sandbox:  SandboxConfig{Agent: "codex"},
		SkillDir: ".codex/skills",
		Skills:   map[string]SkillConfig{"metrics": {Name: "metrics"}},
	}
	state, err := prepareAgentState(scriptDir, instanceDir, "/workspace", "/home/devuser", cfg)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := prepareSkillMounts(cfg, envPath, "/home/devuser", state)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 {
		t.Fatalf("mounts = %#v", mounts)
	}
	if got := strings.Join(skillDockerArgs(mounts), "\x00"); !strings.Contains(got, ":/home/devuser/.codex/skills/metrics:ro") {
		t.Fatalf("Docker skill mount is not read-only at the Codex path: %q", got)
	}
	if _, err := os.Stat(filepath.Join(scriptDir, "claude-dev", "codex-config", "skills", "metrics")); err != nil {
		t.Fatalf("nested mount point was not created in persistent Codex state: %v", err)
	}
}
