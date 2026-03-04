package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
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
	case "set":
		secretsSet(args[1:])
	case "list":
		secretsList()
	case "export":
		secretsExport()
	case "import":
		secretsImport()
	case "edit":
		secretsEdit()
	case "help", "-h", "--help":
		secretsUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown secrets command: %s\n", args[0])
		secretsUsage()
		os.Exit(1)
	}
}

func secretsUsage() {
	fmt.Println("Usage: actl secrets <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init      Generate age key and store in keychain")
	fmt.Println("  set K=V   Set one or more secrets (KEY=VALUE ...)")
	fmt.Println("  list      List secret key names (no decryption)")
	fmt.Println("  export    Decrypt and print KEY=VALUE to stdout")
	fmt.Println("  import    Import KEY=VALUE lines from stdin")
	fmt.Println("  edit      Open decrypted secrets in $EDITOR")
}

func secretsEnvPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".config", "agent-creds", "secrets.env")
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

// sopsEncrypt encrypts a plaintext dotenv file, passing --age directly
// (avoids .sops.yaml path_regex issues with temp files).
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
		"--input-type", "dotenv", "--output-type", "dotenv",
		"--config", "/dev/null",
		plainPath)
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

	// Create config directory and empty secrets.env if it doesn't exist
	envPath := secretsEnvPath()
	if err := os.MkdirAll(filepath.Dir(envPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config dir: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		if err := os.WriteFile(envPath, []byte(""), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", envPath, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Age key stored in keychain (service=%s, key=%s)\n", keychainService, keychainAgeKey)
	fmt.Printf("Recipient: %s\n", recipient)
	fmt.Printf("Secrets file: %s\n", envPath)
}

func secretsSet(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: actl secrets set KEY=VALUE [KEY=VALUE ...]")
		os.Exit(1)
	}

	// Parse KEY=VALUE pairs from args
	newPairs := make(map[string]string)
	for _, arg := range args {
		k, v, ok := strings.Cut(arg, "=")
		if !ok || k == "" {
			fmt.Fprintf(os.Stderr, "Invalid format: %s (expected KEY=VALUE)\n", arg)
			os.Exit(1)
		}
		newPairs[k] = v
	}

	envPath := secretsEnvPath()

	// Load existing secrets (if file exists and is non-empty)
	existing := make(map[string]string)
	var orderedKeys []string
	if info, err := os.Stat(envPath); err == nil && info.Size() > 0 {
		out, err := runSops("--decrypt", envPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting %s: %v\n", envPath, err)
			os.Exit(1)
		}
		existing, orderedKeys = parseDotenv(string(out))
	}

	// Merge new pairs
	for k, v := range newPairs {
		if _, exists := existing[k]; !exists {
			orderedKeys = append(orderedKeys, k)
		}
		existing[k] = v
	}

	// Write plaintext to temp file, then encrypt with sops
	var buf strings.Builder
	for _, k := range orderedKeys {
		buf.WriteString(k + "=" + existing[k] + "\n")
	}

	tmpFile, err := os.CreateTemp("", "secrets-*.env")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp file: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(buf.String()); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "Error writing temp file: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()

	out, err := sopsEncrypt(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting secrets: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(envPath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", envPath, err)
		os.Exit(1)
	}

	for k := range newPairs {
		fmt.Printf("Set %s\n", k)
	}
}

func secretsImport() {
	// Read KEY=VALUE lines from stdin
	newPairs, newKeys := parseDotenv(readStdin())
	if len(newPairs) == 0 {
		fmt.Fprintln(os.Stderr, "No KEY=VALUE lines found on stdin")
		os.Exit(1)
	}

	envPath := secretsEnvPath()

	// Load existing secrets (if file exists and is non-empty)
	existing := make(map[string]string)
	var orderedKeys []string
	if info, err := os.Stat(envPath); err == nil && info.Size() > 0 {
		out, err := runSops("--decrypt", envPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting %s: %v\n", envPath, err)
			os.Exit(1)
		}
		existing, orderedKeys = parseDotenv(string(out))
	}

	// Merge: preserve existing order, append new keys in input order
	for _, k := range newKeys {
		if _, exists := existing[k]; !exists {
			orderedKeys = append(orderedKeys, k)
		}
		existing[k] = newPairs[k]
	}

	// Write plaintext to temp file, then encrypt
	var buf strings.Builder
	for _, k := range orderedKeys {
		buf.WriteString(k + "=" + existing[k] + "\n")
	}

	tmpFile, err := os.CreateTemp("", "secrets-*.env")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp file: %v\n", err)
		os.Exit(1)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(buf.String()); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "Error writing temp file: %v\n", err)
		os.Exit(1)
	}
	tmpFile.Close()

	out, err := sopsEncrypt(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting secrets: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(envPath, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", envPath, err)
		os.Exit(1)
	}

	for _, k := range newKeys {
		fmt.Printf("Set %s\n", k)
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

func secretsList() {
	envPath := secretsEnvPath()
	data, err := os.ReadFile(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No secrets file. Run: actl secrets init")
			return
		}
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", envPath, err)
		os.Exit(1)
	}

	// In SOPS dotenv format, keys are plaintext (only values are encrypted).
	// Lines starting with "sops_" are SOPS metadata.
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Skip sops metadata keys
		if strings.HasPrefix(k, "sops_") {
			continue
		}
		fmt.Println(k)
	}
}

func secretsExport() {
	envPath := secretsEnvPath()
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		return // No secrets file — not an error for export
	}

	// Empty file means no secrets yet
	info, err := os.Stat(envPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if info.Size() == 0 {
		return
	}

	out, err := runSops("--decrypt", envPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting secrets: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}

func secretsEdit() {
	envPath := secretsEnvPath()
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "No secrets file. Run: actl secrets init")
		os.Exit(1)
	}

	// Empty file: encrypt it first so sops can edit it
	info, _ := os.Stat(envPath)
	if info.Size() == 0 {
		// Create a minimal encrypted file so sops edit works
		tmpFile, err := os.CreateTemp("", "secrets-*.env")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		tmpPath := tmpFile.Name()
		tmpFile.WriteString("# Add secrets as KEY=VALUE lines\n")
		tmpFile.Close()
		defer os.Remove(tmpPath)

		out, err := sopsEncrypt(tmpPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing secrets file: %v\n", err)
			os.Exit(1)
		}
		os.WriteFile(envPath, out, 0644)
	}

	if err := runSopsInteractive("--input-type", "dotenv", "--output-type", "dotenv", envPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error editing secrets: %v\n", err)
		os.Exit(1)
	}
}

// parseDotenv parses KEY=VALUE lines, returning a map and ordered key list.
// Skips empty lines, comments, and sops metadata.
func parseDotenv(content string) (map[string]string, []string) {
	pairs := make(map[string]string)
	var keys []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.HasPrefix(k, "sops_") {
			continue
		}
		pairs[k] = v
		keys = append(keys, k)
	}
	return pairs, keys
}
