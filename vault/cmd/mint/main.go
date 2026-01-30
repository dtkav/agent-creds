package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/superfly/macaroon"

	"vault/attestation"
	tfmac "vault/macaroon"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "create":
		createCmd(os.Args[2:])
	case "use":
		useCmd(os.Args[2:])
	case "inspect":
		inspectCmd(os.Args[2:])
	case "setup-yubikey":
		setupYubikeyCmd()
	case "test-attestation":
		testAttestationCmd()
	case "help", "-h", "--help":
		printUsage()
	default:
		// Check if it's a file path (backwards compatibility for one-shot token generation)
		if strings.HasSuffix(os.Args[1], ".akey") {
			// Treat as: mint use <file>
			useCmd(os.Args[1:])
		} else {
			// Old behavior: create a token with flags
			createCmdOld(os.Args[1:])
		}
	}
}

func printUsage() {
	fmt.Println(`mint - Token minting and .akey file management

Usage:
  mint create [flags]          Create a new token or .akey file
  mint use <file.akey>         Get a hot token from an .akey file (requires YubiKey)
  mint inspect <file.akey>     Show the caveats in an .akey file
  mint setup-yubikey           Setup YubiKey for attestation
  mint test-attestation        Test YubiKey attestation

Examples:
  # Create an .akey file for Gmail drafts (requires attestation)
  mint create --hosts gmail.googleapis.com \
              --methods POST \
              --paths "/gmail/v1/users/*/drafts" \
              --require-attestation \
              --valid-for 8760h \
              > ~/.config/agent-creds/gmail-drafts.akey

  # Get a hot token from an .akey file (prompts for YubiKey touch)
  TOKEN=$(mint use ~/.config/agent-creds/gmail-drafts.akey)

  # Or simply:
  TOKEN=$(mint gmail-drafts.akey)

Environment:
  MACAROON_SIGNING_KEY     Base64-encoded signing key (required)
  MACAROON_ENCRYPTION_KEY  Base64-encoded encryption key (required for attestation)
`)
}

// createCmd creates a new token or .akey file
func createCmd(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	hosts := fs.String("hosts", "", "Comma-separated list of allowed hosts")
	methods := fs.String("methods", "", "Comma-separated list of allowed HTTP methods")
	paths := fs.String("paths", "", "Comma-separated list of allowed path patterns")
	validFor := fs.Duration("valid-for", 24*time.Hour, "Token validity duration")
	notBefore := fs.String("not-before", "", "Not valid before (RFC3339 format)")
	requireAttestation := fs.Bool("require-attestation", false, "Require YubiKey attestation (creates .akey)")
	signingKey := fs.String("signing-key", "", "Base64-encoded signing key")
	encryptionKey := fs.String("encryption-key", "", "Base64-encoded encryption key (for attestation)")
	showCaveats := fs.Bool("show-caveats", false, "Show the caveats being added")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	keyStore := loadKeyStore(*signingKey, *encryptionKey)

	m, err := keyStore.NewToken()
	if err != nil {
		log.Fatalf("failed to create token: %v", err)
	}

	// Calculate validity window
	now := time.Now()
	notBeforeTime := now
	if *notBefore != "" {
		notBeforeTime, err = time.Parse(time.RFC3339, *notBefore)
		if err != nil {
			log.Fatalf("invalid not-before time: %v", err)
		}
	}
	notAfterTime := now.Add(*validFor)

	// Add validity window caveat
	if err := m.Add(&macaroon.ValidityWindow{
		NotBefore: notBeforeTime.Unix(),
		NotAfter:  notAfterTime.Unix(),
	}); err != nil {
		log.Fatalf("failed to add validity window: %v", err)
	}

	// Add host caveat
	if *hosts != "" {
		hostList := splitAndTrim(*hosts)
		if err := m.Add(&tfmac.HostCaveat{Hosts: hostList}); err != nil {
			log.Fatalf("failed to add host caveat: %v", err)
		}
	}

	// Add method caveat
	if *methods != "" {
		methodList := splitAndTrim(*methods)
		for i := range methodList {
			methodList[i] = strings.ToUpper(methodList[i])
		}
		if err := m.Add(&tfmac.MethodCaveat{Methods: methodList}); err != nil {
			log.Fatalf("failed to add method caveat: %v", err)
		}
	}

	// Add path caveat
	if *paths != "" {
		pathList := splitAndTrim(*paths)
		if err := m.Add(&tfmac.PathCaveat{Patterns: pathList}); err != nil {
			log.Fatalf("failed to add path caveat: %v", err)
		}
	}

	// Add attestation requirement (3P caveat)
	if *requireAttestation {
		if len(keyStore.EncryptionKey) == 0 {
			log.Fatal("encryption key required for attestation: use -encryption-key or MACAROON_ENCRYPTION_KEY env var")
		}
		if err := attestation.Add3PCaveat(m, keyStore.EncryptionKey); err != nil {
			log.Fatalf("failed to add attestation caveat: %v", err)
		}
	}

	// Encode token
	token, err := tfmac.EncodeToken(m)
	if err != nil {
		log.Fatalf("failed to encode token: %v", err)
	}

	// Output
	if *showCaveats {
		fmt.Fprintln(os.Stderr, "Caveats:")
		fmt.Fprintf(os.Stderr, "  ValidityWindow: %s to %s\n", notBeforeTime.Format(time.RFC3339), notAfterTime.Format(time.RFC3339))
		if *hosts != "" {
			fmt.Fprintf(os.Stderr, "  Hosts: %s\n", *hosts)
		}
		if *methods != "" {
			fmt.Fprintf(os.Stderr, "  Methods: %s\n", *methods)
		}
		if *paths != "" {
			fmt.Fprintf(os.Stderr, "  Paths: %s\n", *paths)
		}
		if *requireAttestation {
			fmt.Fprintln(os.Stderr, "  Attestation: YubiKey required")
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Println(token)
}

// createCmdOld handles legacy flag-based invocation (backwards compatibility)
func createCmdOld(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	hosts := fs.String("hosts", "", "Comma-separated list of allowed hosts")
	methods := fs.String("methods", "", "Comma-separated list of allowed HTTP methods")
	paths := fs.String("paths", "", "Comma-separated list of allowed path patterns")
	validFor := fs.Duration("valid-for", 24*time.Hour, "Token validity duration")
	notBefore := fs.String("not-before", "", "Not valid before (RFC3339 format)")
	requireAttestation := fs.Bool("require-attestation", false, "Require YubiKey attestation")
	signingKey := fs.String("signing-key", "", "Base64-encoded signing key")
	encryptionKey := fs.String("encryption-key", "", "Base64-encoded encryption key")
	showCaveats := fs.Bool("show-caveats", false, "Show the caveats being added")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	// Build args for createCmd
	var newArgs []string
	if *hosts != "" {
		newArgs = append(newArgs, "--hosts", *hosts)
	}
	if *methods != "" {
		newArgs = append(newArgs, "--methods", *methods)
	}
	if *paths != "" {
		newArgs = append(newArgs, "--paths", *paths)
	}
	if *validFor != 24*time.Hour {
		newArgs = append(newArgs, "--valid-for", validFor.String())
	}
	if *notBefore != "" {
		newArgs = append(newArgs, "--not-before", *notBefore)
	}
	if *requireAttestation {
		newArgs = append(newArgs, "--require-attestation")
	}
	if *signingKey != "" {
		newArgs = append(newArgs, "--signing-key", *signingKey)
	}
	if *encryptionKey != "" {
		newArgs = append(newArgs, "--encryption-key", *encryptionKey)
	}
	if *showCaveats {
		newArgs = append(newArgs, "--show-caveats")
	}

	createCmd(newArgs)
}

// useCmd gets a hot token from an .akey file
func useCmd(args []string) {
	if len(args) == 0 {
		log.Fatal("usage: mint use <file.akey>")
	}

	akeyPath := args[0]

	// Read the .akey file
	content, err := os.ReadFile(akeyPath)
	if err != nil {
		// Try in config directory
		configPath := filepath.Join(os.Getenv("HOME"), ".config", "agent-creds", akeyPath)
		content, err = os.ReadFile(configPath)
		if err != nil {
			log.Fatalf("failed to read .akey file: %v", err)
		}
	}

	mainToken := strings.TrimSpace(string(content))
	if mainToken == "" {
		log.Fatal(".akey file is empty")
	}

	// Decode the token to check for attestation requirement
	m, err := tfmac.DecodeToken(mainToken)
	if err != nil {
		log.Fatalf("failed to decode token: %v", err)
	}

	// Check if attestation is required (has 3P caveat)
	caveats := m.UnsafeCaveats
	has3P := false
	for _, c := range caveats.Caveats {
		if _, ok := c.(*macaroon.Caveat3P); ok {
			has3P = true
			break
		}
	}

	if !has3P {
		// No attestation required, just output the token
		fmt.Println(mainToken)
		return
	}

	// Load encryption key for discharge
	keyStore := loadKeyStore("", "")
	if len(keyStore.EncryptionKey) == 0 {
		log.Fatal("encryption key required: set MACAROON_ENCRYPTION_KEY env var")
	}

	// Check YubiKey availability
	if !attestation.IsAvailable() {
		log.Fatal("YubiKey tools not found. Run 'mint setup-yubikey' for setup instructions.")
	}

	// Create session manager and authenticate
	sessionMgr := attestation.NewSessionManager(keyStore.EncryptionKey)
	yk := attestation.NewYubiKey(2)

	if err := sessionMgr.StartSession(yk); err != nil {
		log.Fatalf("YubiKey attestation failed: %v", err)
	}
	defer sessionMgr.ClearSession()

	// Create discharge token
	discharge, err := sessionMgr.CreateDischarge(m)
	if err != nil {
		log.Fatalf("failed to create discharge: %v", err)
	}

	dischargeStr, err := attestation.EncodeDischarge(discharge)
	if err != nil {
		log.Fatalf("failed to encode discharge: %v", err)
	}

	// Output combined token
	fmt.Println(attestation.CombineTokens(mainToken, dischargeStr))
}

// inspectCmd shows the caveats in an .akey file
func inspectCmd(args []string) {
	if len(args) == 0 {
		log.Fatal("usage: mint inspect <file.akey>")
	}

	akeyPath := args[0]

	// Read the .akey file
	content, err := os.ReadFile(akeyPath)
	if err != nil {
		configPath := filepath.Join(os.Getenv("HOME"), ".config", "agent-creds", akeyPath)
		content, err = os.ReadFile(configPath)
		if err != nil {
			log.Fatalf("failed to read .akey file: %v", err)
		}
	}

	tokenStr := strings.TrimSpace(string(content))
	if tokenStr == "" {
		log.Fatal(".akey file is empty")
	}

	m, err := tfmac.DecodeToken(tokenStr)
	if err != nil {
		log.Fatalf("failed to decode token: %v", err)
	}

	caveats := m.UnsafeCaveats
	fmt.Println("Caveats:")
	for _, c := range caveats.Caveats {
		switch cv := c.(type) {
		case *macaroon.ValidityWindow:
			notBefore := time.Unix(cv.NotBefore, 0)
			notAfter := time.Unix(cv.NotAfter, 0)
			fmt.Printf("  ValidityWindow: %s to %s\n", notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339))
		case *tfmac.HostCaveat:
			fmt.Printf("  Hosts: %s\n", strings.Join(cv.Hosts, ", "))
		case *tfmac.MethodCaveat:
			fmt.Printf("  Methods: %s\n", strings.Join(cv.Methods, ", "))
		case *tfmac.PathCaveat:
			fmt.Printf("  Paths: %s\n", strings.Join(cv.Patterns, ", "))
		case *macaroon.Caveat3P:
			fmt.Printf("  Third-party: %s (attestation required)\n", cv.Location)
		default:
			fmt.Printf("  Unknown: %T\n", c)
		}
	}
}

// setupYubikeyCmd prints YubiKey setup instructions
func setupYubikeyCmd() {
	fmt.Println(attestation.SetupInfo())
}

// testAttestationCmd tests YubiKey attestation
func testAttestationCmd() {
	if !attestation.IsAvailable() {
		fmt.Println("YubiKey tools not found.")
		fmt.Println()
		fmt.Println(attestation.SetupInfo())
		os.Exit(1)
	}

	fmt.Println("YubiKey tools found.")
	fmt.Println()

	// Generate challenge
	challenge, err := attestation.GenerateChallenge()
	if err != nil {
		log.Fatalf("failed to generate challenge: %v", err)
	}

	fmt.Println("Testing HMAC-SHA1 challenge-response on slot 2...")
	fmt.Println("Touch your YubiKey when it blinks...")

	yk := attestation.NewYubiKey(2)
	response, err := yk.ChallengeResponse(challenge)
	if err != nil {
		log.Fatalf("YubiKey challenge-response failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Success! YubiKey attestation is working.")
	fmt.Printf("Response length: %d bytes\n", len(response))
}

// loadKeyStore loads signing and encryption keys from flags or environment
func loadKeyStore(signingKeyFlag, encryptionKeyFlag string) *tfmac.KeyStore {
	signingKeyB64 := signingKeyFlag
	if signingKeyB64 == "" {
		signingKeyB64 = os.Getenv("MACAROON_SIGNING_KEY")
	}
	if signingKeyB64 == "" {
		log.Fatal("signing key required: use -signing-key or MACAROON_SIGNING_KEY env var")
	}

	signingKey, err := base64.StdEncoding.DecodeString(signingKeyB64)
	if err != nil {
		log.Fatalf("invalid signing key: %v", err)
	}

	var encryptionKey macaroon.EncryptionKey
	encKeyB64 := encryptionKeyFlag
	if encKeyB64 == "" {
		encKeyB64 = os.Getenv("MACAROON_ENCRYPTION_KEY")
	}
	if encKeyB64 != "" {
		encKey, err := base64.StdEncoding.DecodeString(encKeyB64)
		if err != nil {
			log.Fatalf("invalid encryption key: %v", err)
		}
		if len(encKey) != macaroon.EncryptionKeySize {
			log.Fatalf("encryption key must be %d bytes", macaroon.EncryptionKeySize)
		}
		encryptionKey = macaroon.EncryptionKey(encKey)
	}

	return &tfmac.KeyStore{
		SigningKey:    macaroon.SigningKey(signingKey),
		EncryptionKey: encryptionKey,
		KeyID:         []byte("primary"),
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
