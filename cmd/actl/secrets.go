package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
	vaultcfg "vault/vault"
)

const (
	keychainService = "agent-creds"
	keychainAgeKey  = "age-secret-key"
)

func runSecrets(args []string) {
	if len(args) == 0 {
		secretsUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "init":
		secretsInit()
	case "edit":
		secretsEdit()
	case "show":
		secretsShow(args[1:])
	case "decrypt":
		secretsDecrypt(args[1:])
	case "import":
		secretsImport(args[1:])
	case "reload":
		secretsReload(args[1:])
	case "env":
		secretsEnv(args[1:])
	case "export":
		secretsExportLegacy()
	case "credentials":
		runCredentials(args[1:])
	case "log":
		runAuditLog(args[1:])
	case "help", "-h", "--help":
		secretsUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown vault command: %s\n", args[0])
		secretsUsage()
		os.Exit(1)
	}
}

func secretsUsage() {
	fmt.Print(`Usage: actl vault <command>

Commands:
  init              Generate age key and create vault.yaml
  edit              Open vault.yaml in $EDITOR (decrypts/re-encrypts)
  show              Decrypt and print vault.yaml to stdout
  show --credentials  List credentials with masked secrets
  show --capabilities <path>  Show credential capabilities
  decrypt <path>    Decrypt vault.yaml to a file (for mounting into containers)
  import <file>     Import KEY=VALUE pairs into secrets (keyed by file path)
  env [file]        Print KEY=VALUE for secrets (default: .auth.env)
  reload            Atomically apply vault.yaml to the running local Vault
  credentials add   Add a new credential interactively
  log               Display audit log entries

Import examples:
  actl vault import auth.env
  actl vault import auth.staging.env
`)
}

func secretsReload(args []string) {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "Usage: actl vault reload")
		os.Exit(1)
	}
	yamlPath := vaultYAMLPath()
	config, err := runSops("--decrypt", yamlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting vault.yaml: %v\n", err)
		os.Exit(1)
	}

	containerOutput, err := exec.Command(
		"docker", "ps",
		"--filter", "label=com.docker.compose.project=agent-creds",
		"--filter", "label=com.docker.compose.service=vault",
		"--format", "{{.ID}}",
	).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding local Vault container: %v\n", err)
		os.Exit(1)
	}
	containers := strings.Fields(string(containerOutput))
	if len(containers) != 1 {
		fmt.Fprintf(os.Stderr, "Error: expected one running local Vault container, found %d\n", len(containers))
		os.Exit(1)
	}

	cmd := exec.Command("docker", "exec", "-i", containers[0], "/app/vaultctl", "reload")
	cmd.Stdin = bytes.NewReader(config)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Vault config was not changed.")
		os.Exit(1)
	}
}

func vaultYAMLPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".config", "agent-creds", "vault.yaml")
}

// getAgeKey retrieves the age private key from the system keychain.
func getAgeKey() (string, error) {
	return keyring.Get(keychainService, keychainAgeKey)
}

// getOrCreateAgeKey returns the age private key, creating one if it doesn't exist.
func getOrCreateAgeKey() (string, error) {
	key, err := keyring.Get(keychainService, keychainAgeKey)
	if err == nil {
		return key, nil
	}
	if err != keyring.ErrNotFound {
		return "", fmt.Errorf("keychain error: %w", err)
	}

	// Generate new age identity
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generating age key: %w", err)
	}

	privKey := identity.String()
	if err := keyring.Set(keychainService, keychainAgeKey, privKey); err != nil {
		return "", fmt.Errorf("storing key in keychain: %w", err)
	}

	return privKey, nil
}

// ageRecipient derives the public recipient from an age private key string.
func ageRecipient(privKey string) (string, error) {
	identity, err := age.ParseX25519Identity(privKey)
	if err != nil {
		return "", fmt.Errorf("parsing age key: %w", err)
	}
	return identity.Recipient().String(), nil
}

// runSops executes sops with SOPS_AGE_KEY set from keychain.
func runSops(args ...string) ([]byte, error) {
	key, err := getAgeKey()
	if err != nil {
		return nil, fmt.Errorf("retrieving age key from keychain: %w", err)
	}

	cmd := exec.Command("sops", args...)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// runSopsInteractive executes sops with stdin/stdout/stderr attached.
func runSopsInteractive(args ...string) error {
	key, err := getAgeKey()
	if err != nil {
		return fmt.Errorf("retrieving age key from keychain: %w", err)
	}

	cmd := exec.Command("sops", args...)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// sopsEncrypt encrypts a plaintext YAML file. Only values under the "secrets" key are encrypted.
func sopsEncrypt(plainPath string) ([]byte, error) {
	key, err := getAgeKey()
	if err != nil {
		return nil, fmt.Errorf("retrieving age key from keychain: %w", err)
	}
	recipient, err := ageRecipient(key)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("sops", "--encrypt",
		"--age", recipient,
		"--encrypted-regex", "^secrets$",
		"--input-type", "yaml", "--output-type", "yaml",
		"--config", "/dev/null",
		plainPath)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func validateVaultYAML(plaintext []byte) error {
	config, err := vaultcfg.LoadBytes(plaintext)
	if err != nil {
		return err
	}
	if _, err := config.Validate(); err != nil {
		return err
	}
	return nil
}

// saveVaultYAML validates plaintext before encrypting it and atomically
// replacing the saved file. A validation or encryption failure leaves the
// existing encrypted document untouched.
func saveVaultYAML(yamlPath string, plaintext []byte) error {
	if err := validateVaultYAML(plaintext); err != nil {
		return fmt.Errorf("invalid vault config: %w", err)
	}

	plainFile, err := os.CreateTemp("", "vault-save-*.yaml")
	if err != nil {
		return err
	}
	plainPath := plainFile.Name()
	defer os.Remove(plainPath)
	if _, err := plainFile.Write(plaintext); err != nil {
		plainFile.Close()
		return err
	}
	if err := plainFile.Close(); err != nil {
		return err
	}

	encrypted, err := sopsEncrypt(plainPath)
	if err != nil {
		return fmt.Errorf("encrypting vault config: %w", err)
	}

	encryptedFile, err := os.CreateTemp(filepath.Dir(yamlPath), ".vault-*.yaml")
	if err != nil {
		return err
	}
	encryptedPath := encryptedFile.Name()
	defer os.Remove(encryptedPath)
	if err := encryptedFile.Chmod(0600); err != nil {
		encryptedFile.Close()
		return err
	}
	if _, err := encryptedFile.Write(encrypted); err != nil {
		encryptedFile.Close()
		return err
	}
	if err := encryptedFile.Sync(); err != nil {
		encryptedFile.Close()
		return err
	}
	if err := encryptedFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(encryptedPath, yamlPath); err != nil {
		return err
	}
	return nil
}

func editPlaintextFile(path string) error {
	editor := strings.TrimSpace(os.Getenv("SOPS_EDITOR"))
	if editor == "" {
		editor = strings.TrimSpace(os.Getenv("VISUAL"))
	}
	if editor == "" {
		editor = strings.TrimSpace(os.Getenv("EDITOR"))
	}
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command("/bin/sh", "-c", editor+` "$@"`, "actl-vault-editor", path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func vaultTemplate(signingKey, encryptionKey string) string {
	return fmt.Sprintf(`secrets:
  vault:
    SIGNING_KEY: %s
    ENCRYPTION_KEY: %s

signing_key:
  $secret: 'vault#SIGNING_KEY'
encryption_key:
  $secret: 'vault#ENCRYPTION_KEY'

credentials: {}
`, signingKey, encryptionKey)
}

func secretsInit() {
	privKey, err := getOrCreateAgeKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	recipient, err := ageRecipient(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	yamlPath := vaultYAMLPath()
	if err := os.MkdirAll(filepath.Dir(yamlPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config dir: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stat(yamlPath); err == nil {
		fmt.Printf("vault.yaml already exists: %s\n", yamlPath)
		fmt.Printf("Age recipient: %s\n", recipient)
		return
	}

	// Generate signing key
	sigKey := make([]byte, 32)
	if _, err := rand.Read(sigKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating signing key: %v\n", err)
		os.Exit(1)
	}
	// Third-party caveats use a separate 32-byte encryption key.
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating encryption key: %v\n", err)
		os.Exit(1)
	}

	plaintext := []byte(vaultTemplate(
		base64.StdEncoding.EncodeToString(sigKey),
		base64.StdEncoding.EncodeToString(encKey),
	))
	if err := saveVaultYAML(yamlPath, plaintext); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", yamlPath, err)
		os.Exit(1)
	}

	fmt.Printf("Age key stored in keychain (service=%s)\n", keychainService)
	fmt.Printf("Recipient: %s\n", recipient)
	fmt.Printf("Vault config: %s\n", yamlPath)
	fmt.Println("\nEdit with: actl vault edit")
}

func secretsEdit() {
	yamlPath := vaultYAMLPath()
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No vault.yaml found. Run: actl vault init")
		os.Exit(1)
	}

	if err := editVaultFile(yamlPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error editing vault: %v\n", err)
		os.Exit(1)
	}
}

func editVaultFile(yamlPath string) error {
	plaintext, err := runSops("--decrypt", yamlPath)
	if err != nil {
		return fmt.Errorf("decrypting vault: %w", err)
	}

	plainFile, err := os.CreateTemp("", "vault-edit-*.yaml")
	if err != nil {
		return err
	}
	plainPath := plainFile.Name()
	defer os.Remove(plainPath)
	if _, err := plainFile.Write(plaintext); err != nil {
		plainFile.Close()
		return err
	}
	if err := plainFile.Close(); err != nil {
		return err
	}

	if err := editPlaintextFile(plainPath); err != nil {
		return err
	}
	edited, err := os.ReadFile(plainPath)
	if err != nil {
		return err
	}
	if err := saveVaultYAML(yamlPath, edited); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}
	return nil
}

func secretsShow(args []string) {
	credentials := false
	capabilitiesPath := ""
	for i, a := range args {
		if a == "--credentials" {
			credentials = true
		}
		if a == "--capabilities" && i+1 < len(args) {
			capabilitiesPath = args[i+1]
		}
	}

	yamlPath := vaultYAMLPath()
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No vault.yaml found. Run: actl vault init")
		os.Exit(1)
	}

	out, err := runSops("--decrypt", yamlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting vault: %v\n", err)
		os.Exit(1)
	}

	if !credentials && capabilitiesPath == "" {
		os.Stdout.Write(out)
		return
	}

	var cfg struct {
		Credentials map[string]credentialShowConfig `yaml:"credentials"`
	}
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing vault.yaml: %v\n", err)
		os.Exit(1)
	}

	if capabilitiesPath != "" {
		showCapabilities(cfg.Credentials, capabilitiesPath)
		return
	}

	if len(cfg.Credentials) == 0 {
		fmt.Println("No credentials configured.")
		return
	}

	for path, cc := range cfg.Credentials {
		fmt.Printf("/%s\n", path)
		fmt.Printf("  type: %s\n", cc.Type)

		// Env var names
		if cc.Env != "" {
			fmt.Printf("  env: %s\n", cc.Env)
		}
		if cc.EnvUser != "" {
			fmt.Printf("  env_user: %s\n", cc.EnvUser)
		}
		if cc.EnvPass != "" {
			fmt.Printf("  env_pass: %s\n", cc.EnvPass)
		}

		// Masked secrets
		if cc.Token != "" {
			fmt.Printf("  token: %s\n", maskSecret(string(cc.Token)))
		}
		if cc.Username != "" {
			fmt.Printf("  username: %s\n", cc.Username)
		}
		if cc.Password != "" {
			fmt.Printf("  password: %s\n", maskSecret(string(cc.Password)))
		}
		if cc.AccessKeyID != "" {
			fmt.Printf("  access_key_id: %s\n", maskSecret(string(cc.AccessKeyID)))
		}
		if cc.SecretAccessKey != "" {
			fmt.Printf("  secret_access_key: %s\n", maskSecret(string(cc.SecretAccessKey)))
		}

		// Host hints from capabilities
		if cc.Capabilities != nil && len(cc.Capabilities.Hosts) > 0 {
			fmt.Printf("  hosts: %s\n", strings.Join(cc.Capabilities.Hosts, ", "))
		}

		fmt.Println()
	}
}

func showCapabilities(credentials map[string]credentialShowConfig, path string) {
	// Normalize: strip leading /
	lookup := strings.TrimPrefix(path, "/")

	cc, ok := credentials[lookup]
	if !ok {
		fmt.Fprintf(os.Stderr, "Credential not found: /%s\n", lookup)
		os.Exit(1)
	}

	fmt.Printf("/%s (type: %s)\n\n", lookup, cc.Type)

	if cc.Capabilities == nil {
		fmt.Println("No capabilities defined for this credential.")
		return
	}

	if len(cc.Capabilities.Hosts) > 0 {
		fmt.Println("Allowed hosts:")
		for _, h := range cc.Capabilities.Hosts {
			fmt.Printf("  - %s\n", h)
		}
		fmt.Println()
	}

	if len(cc.Capabilities.Endpoints) == 0 {
		fmt.Println("No endpoints defined.")
		return
	}

	fmt.Println("Endpoints:")
	for _, ep := range cc.Capabilities.Endpoints {
		methods := strings.Join(ep.Methods, ", ")
		paths := strings.Join(ep.Paths, ", ")
		fmt.Printf("  %s %s\n", methods, paths)
		if ep.Description != "" {
			fmt.Printf("    %s\n", ep.Description)
		}
	}
}

// credentialShowConfig mirrors the credential fields needed for display.
type credentialShowConfig struct {
	Type            string               `yaml:"type"`
	Token           credentialShowSecret `yaml:"token,omitempty"`
	Username        credentialShowSecret `yaml:"username,omitempty"`
	Password        credentialShowSecret `yaml:"password,omitempty"`
	Env             string               `yaml:"env,omitempty"`
	EnvUser         string               `yaml:"env_user,omitempty"`
	EnvPass         string               `yaml:"env_pass,omitempty"`
	AccessKeyID     credentialShowSecret `yaml:"access_key_id,omitempty"`
	SecretAccessKey credentialShowSecret `yaml:"secret_access_key,omitempty"`
	Capabilities    *credentialShowCaps  `yaml:"capabilities,omitempty"`
}

// credentialShowSecret accepts either a literal scalar or the {$secret: ref}
// form written by `actl vault credentials add`. It never resolves the ref;
// masked inventory output must not load or print secret values.
type credentialShowSecret string

func (s *credentialShowSecret) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*s = credentialShowSecret(node.Value)
		return nil
	case yaml.MappingNode:
		if len(node.Content) == 2 && node.Content[0].Value == "$secret" {
			*s = credentialShowSecret("$secret:" + node.Content[1].Value)
			return nil
		}
	}
	return fmt.Errorf("credential secret must be a string or $secret reference")
}

type credentialShowCaps struct {
	Hosts     []string                 `yaml:"hosts,omitempty"`
	Endpoints []credentialShowEndpoint `yaml:"endpoints,omitempty"`
}

type credentialShowEndpoint struct {
	Methods     []string `yaml:"methods"`
	Paths       []string `yaml:"paths"`
	Description string   `yaml:"description,omitempty"`
}

// maskSecret shows only the last 4 characters, replacing the rest with asterisks.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
}

func secretsDecrypt(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: actl vault decrypt <output-path>")
		os.Exit(1)
	}
	outPath := args[0]

	yamlPath := vaultYAMLPath()
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No vault.yaml found. Run: actl vault init")
		os.Exit(1)
	}

	out, err := runSops("--decrypt", yamlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting vault: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, out, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
		os.Exit(1)
	}
}

// secretsEnv decrypts vault.yaml, finds the secrets group keyed by the given
// file path (default: $PWD/.auth.env), and prints KEY=VALUE lines to stdout.
func secretsEnv(args []string) {
	file := ".auth.env"
	if len(args) > 0 {
		file = args[0]
	}

	absPath, err := filepath.Abs(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	yamlPath := vaultYAMLPath()
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No vault.yaml found. Run: actl vault init")
		os.Exit(1)
	}

	out, err := runSops("--decrypt", yamlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting vault: %v\n", err)
		os.Exit(1)
	}

	var doc struct {
		Secrets map[string]map[string]string `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing vault.yaml: %v\n", err)
		os.Exit(1)
	}

	group, ok := doc.Secrets[absPath]
	if !ok {
		fmt.Fprintf(os.Stderr, "No secrets found for %s\n", absPath)
		os.Exit(1)
	}

	for k, v := range group {
		fmt.Printf("%s='%s'\n", k, strings.ReplaceAll(v, "'", "'\"'\"'"))
	}
}

// secretsExportLegacy decrypts the legacy secrets.env and prints KEY=VALUE to stdout.
// Used by adev for backward compatibility when vault.yaml doesn't exist.
func secretsExportLegacy() {
	home, err := os.UserHomeDir()
	if err != nil {
		os.Exit(1)
	}
	envPath := filepath.Join(home, ".config", "agent-creds", "secrets.env")
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		return // no legacy file, silent exit
	}

	out, err := runSops("--decrypt", envPath)
	if err != nil {
		os.Exit(1)
	}
	os.Stdout.Write(out)
}

// secretsImport reads KEY=VALUE pairs from a file and merges them into
// secrets.<path> in vault.yaml. The group key is the file path as given.
//
// Usage: actl vault import <file>
func secretsImport(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: actl vault import <file>")
		os.Exit(1)
	}

	filePath := args[0]
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}
	group := absPath

	yamlPath := vaultYAMLPath()
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No vault.yaml found. Run: actl vault init")
		os.Exit(1)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", absPath, err)
		os.Exit(1)
	}

	newPairs := parseDotenv(string(data))
	if len(newPairs) == 0 {
		fmt.Fprintln(os.Stderr, "No KEY=VALUE pairs found")
		os.Exit(1)
	}

	// Decrypt existing vault.yaml
	out, err := runSops("--decrypt", yamlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting vault.yaml: %v\n", err)
		os.Exit(1)
	}

	// Parse YAML
	var doc yaml.Node
	if err := yaml.Unmarshal(out, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing vault.yaml: %v\n", err)
		os.Exit(1)
	}

	// Find or create secrets.<group> mapping node
	root := doc.Content[0] // document root mapping
	secretsNode := findOrCreateMapping(root, "secrets")
	groupNode := findOrCreateMapping(secretsNode, group)

	// Merge new pairs into secrets.<group>
	for k, v := range newPairs {
		setMappingValue(groupNode, k, v)
	}

	// Validate, encrypt, and atomically replace the saved config.
	modified, err := yaml.Marshal(&doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing vault.yaml: %v\n", err)
		os.Exit(1)
	}

	if err := saveVaultYAML(yamlPath, modified); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", yamlPath, err)
		os.Exit(1)
	}

	fmt.Printf("Imported %d keys into %s\n", len(newPairs), group)
	for k := range newPairs {
		fmt.Printf("  %s\n", k)
	}
}

func readStdin() string {
	var buf strings.Builder
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		buf.WriteString(scanner.Text() + "\n")
	}
	return buf.String()
}

// parseDotenv parses KEY=VALUE lines, skipping comments and blank lines.
func parseDotenv(content string) map[string]string {
	pairs := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			continue
		}
		pairs[k] = v
	}
	return pairs
}

// findOrCreateMapping finds a mapping node by key, or creates one if missing.
func findOrCreateMapping(root *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(root.Content)-1; i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i+1]
		}
	}
	// Create new mapping
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode}
	root.Content = append(root.Content, keyNode, valNode)
	return valNode
}

// setMappingValue sets a key in a mapping node, updating if exists.
func setMappingValue(mapping *yaml.Node, key, value string) {
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1].Value = value
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value},
	)
}
