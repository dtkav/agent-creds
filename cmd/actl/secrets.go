package main

import (
	"bufio"
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
		secretsShow()
	case "decrypt":
		secretsDecrypt(args[1:])
	case "import":
		secretsImport(args[1:])
	case "env":
		secretsEnv(args[1:])
	case "export":
		secretsExportLegacy()
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
  decrypt <path>    Decrypt vault.yaml to a file (for mounting into containers)
  import <file>     Import KEY=VALUE pairs into secrets (keyed by file path)
  env [file]        Print KEY=VALUE for secrets (default: .auth.env)

Import examples:
  actl vault import auth.env
  actl vault import auth.staging.env
`)
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

func vaultTemplate(signingKey string) string {
	return fmt.Sprintf(`secrets:
  vault:
    SIGNING_KEY: %s

signing_key:
  $secret: 'vault#SIGNING_KEY'

credentials: {}
`, signingKey)
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

	// Write template to temp file, encrypt, write to final path
	tmpFile, err := os.CreateTemp("", "vault-*.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(vaultTemplate(base64.StdEncoding.EncodeToString(sigKey))); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()

	out, err := sopsEncrypt(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting vault.yaml: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(yamlPath, out, 0600); err != nil {
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

	if err := runSopsInteractive(yamlPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error editing vault: %v\n", err)
		os.Exit(1)
	}
}

func secretsShow() {
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
	os.Stdout.Write(out)
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
		fmt.Printf("%s=%s\n", k, v)
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

	// Write modified YAML to temp file
	modified, err := yaml.Marshal(&doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing vault.yaml: %v\n", err)
		os.Exit(1)
	}

	tmpFile, err := os.CreateTemp("", "vault-*.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(modified); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()

	// Re-encrypt
	encrypted, err := sopsEncrypt(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting vault.yaml: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(yamlPath, encrypted, 0600); err != nil {
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
