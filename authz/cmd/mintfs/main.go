package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"authz/api/client"
	"authz/attestation"
	tfmac "authz/macaroon"
	"authz/mintfs"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		startCmd(os.Args[2:])
	case "stop":
		stopCmd(os.Args[2:])
	case "status":
		statusCmd(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		// Assume it's a mount point
		startCmd(os.Args[1:])
	}
}

func printUsage() {
	fmt.Println(`mintfs - FUSE filesystem for session-based token generation

Usage:
  mintfs start <mountpoint> [options]   Mount the filesystem
  mintfs stop <mountpoint>              Unmount the filesystem
  mintfs status                         Show mounted filesystems

Options:
  --ssh <host>         SSH server for token minting (e.g., "localhost -p 2222")
  --hosts <list>       Comma-separated hosts for SSH mode (e.g., "api.stripe.com,api.openai.com")
  --user <username>    Username for server authentication
  --server <url>       Server URL (default: http://localhost:8080)
  --insecure           Skip TLS verification

Examples:
  # SSH mode (uses ssh-agent for authentication)
  mintfs start ~/.mintfs --ssh "localhost -p 2222" --hosts api.stripe.com,api.openai.com

  # Local mode (touch YubiKey once at start)
  mintfs start ~/.mintfs

  # Server mode (authenticate with YubiKey via server)
  mintfs start ~/.mintfs --user alice --server https://authz.example.com

  # Read tokens without additional YubiKey touches
  TOKEN=$(cat ~/.mintfs/api.stripe.com)

  # Use in curl
  curl -H "Authorization: Bearer $(cat ~/.mintfs/api.stripe.com)" \
    https://api.stripe.com/v1/customers

  # Stop mintfs
  mintfs stop ~/.mintfs

SSH mode uses your SSH key to authenticate with the authz SSH server.
Local mode loads .akey files from ~/.config/agent-creds/.
Server mode fetches tokens from the authz HTTP server.

Environment:
  MACAROON_SIGNING_KEY     Base64-encoded signing key (local mode)
  MACAROON_ENCRYPTION_KEY  Base64-encoded encryption key (local mode)
  AKEY_DIR                 Directory with .akey files (default: ~/.config/agent-creds)
  AUTHZ_SERVER             Server URL for server mode
  AUTHZ_USER               Username for server mode
  AUTHZ_SSH                SSH server for SSH mode
`)
}

func startCmd(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	sshHost := fs.String("ssh", os.Getenv("AUTHZ_SSH"), "SSH server for token minting")
	hosts := fs.String("hosts", "", "Comma-separated hosts for SSH mode")
	username := fs.String("user", os.Getenv("AUTHZ_USER"), "Username for server authentication")
	serverURL := fs.String("server", os.Getenv("AUTHZ_SERVER"), "Server URL")
	insecure := fs.Bool("insecure", false, "Skip TLS verification")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if fs.NArg() == 0 {
		log.Fatal("usage: mintfs start <mountpoint> [options]")
	}

	mountPoint := fs.Arg(0)

	// Expand ~ in path
	if len(mountPoint) > 1 && mountPoint[:2] == "~/" {
		home, _ := os.UserHomeDir()
		mountPoint = filepath.Join(home, mountPoint[2:])
	}

	// Create mount point if needed
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		log.Fatalf("failed to create mount point: %v", err)
	}

	// Decide mode based on options
	if *sshHost != "" {
		// SSH mode
		hostList := parseHosts(*hosts)
		if len(hostList) == 0 {
			// Default hosts
			hostList = []string{"api.stripe.com", "api.openai.com", "api.anthropic.com"}
		}
		startSSHMode(mountPoint, *sshHost, hostList)
	} else if *username != "" && *serverURL != "" {
		// Server mode
		startServerMode(mountPoint, *username, *serverURL, *insecure)
	} else if *username != "" || *serverURL != "" {
		log.Fatal("Both --user and --server are required for server mode")
	} else {
		// Local mode
		startLocalMode(mountPoint)
	}
}

// parseHosts splits a comma-separated list of hosts
func parseHosts(s string) []string {
	if s == "" {
		return nil
	}
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// startSSHMode starts mintfs in SSH mode
func startSSHMode(mountPoint, sshHost string, hosts []string) {
	fmt.Printf("Starting mintfs in SSH mode\n")
	fmt.Printf("SSH server: %s\n", sshHost)
	fmt.Printf("Hosts: %v\n", hosts)
	fmt.Printf("Mounting at %s...\n", mountPoint)

	// Create and mount the filesystem
	mfs, err := mintfs.NewWithSSH(mountPoint, sshHost, hosts)
	if err != nil {
		log.Fatalf("failed to create filesystem: %v", err)
	}

	serveFilesystem(mfs, mountPoint)
}

// startServerMode starts mintfs in server mode
func startServerMode(mountPoint, username, serverURL string, insecure bool) {
	// Check YubiKey availability
	if !attestation.IsAvailable() {
		log.Fatal("YubiKey tools not found. Run 'mint setup-yubikey' for setup instructions.")
	}

	// Create API client
	apiClient := client.NewClient(serverURL, insecure)

	// Authenticate with server via FIDO2
	fmt.Printf("Authenticating as %s with server %s...\n", username, serverURL)

	// Get challenge from server
	challenge, err := apiClient.GetAuthChallenge(username)
	if err != nil {
		log.Fatalf("Failed to get challenge: %v", err)
	}

	// Decode challenge
	challengeBytes, err := client.DecodeChallenge(challenge.Challenge)
	if err != nil {
		log.Fatalf("Failed to decode challenge: %v", err)
	}

	// Perform FIDO2 assertion with YubiKey
	fmt.Println("Touch your YubiKey to authenticate...")
	assertion, err := performFIDO2Assertion(challenge, challengeBytes)
	if err != nil {
		log.Fatalf("FIDO2 authentication failed: %v", err)
	}

	// Verify with server
	resp, err := apiClient.VerifyAuth(assertion)
	if err != nil {
		log.Fatalf("Server verification failed: %v", err)
	}

	fmt.Printf("Authenticated as %s!\n", resp.Username)
	fmt.Printf("Mounting at %s...\n", mountPoint)

	// Create and mount the filesystem
	mfs, err := mintfs.NewWithAPI(mountPoint, apiClient)
	if err != nil {
		log.Fatalf("failed to create filesystem: %v", err)
	}

	serveFilesystem(mfs, mountPoint)
}

// startLocalMode starts mintfs in local mode
func startLocalMode(mountPoint string) {
	// Load key store
	keyStore, err := tfmac.LoadKeyStore()
	if err != nil {
		log.Fatalf("failed to load keys: %v", err)
	}

	if len(keyStore.EncryptionKey) == 0 {
		log.Fatal("MACAROON_ENCRYPTION_KEY required for mintfs")
	}

	// Check YubiKey availability
	if !attestation.IsAvailable() {
		log.Fatal("YubiKey tools not found. Run 'mint setup-yubikey' for setup instructions.")
	}

	// Get akey directory
	akeyDir := os.Getenv("AKEY_DIR")
	if akeyDir == "" {
		home, _ := os.UserHomeDir()
		akeyDir = filepath.Join(home, ".config", "agent-creds")
	}

	// Create akey directory if it doesn't exist
	if err := os.MkdirAll(akeyDir, 0700); err != nil {
		log.Fatalf("failed to create akey directory: %v", err)
	}

	// Authenticate with YubiKey
	fmt.Println("Authenticating with YubiKey...")
	sessionMgr := attestation.NewSessionManager(keyStore.EncryptionKey)
	yk := attestation.NewYubiKey(2)

	if err := sessionMgr.StartSession(yk); err != nil {
		log.Fatalf("YubiKey attestation failed: %v", err)
	}

	fmt.Println("YubiKey authenticated!")
	fmt.Printf("Mounting at %s...\n", mountPoint)

	// Create and mount the filesystem
	mfs, err := mintfs.New(mountPoint, akeyDir, sessionMgr)
	if err != nil {
		log.Fatalf("failed to create filesystem: %v", err)
	}

	serveFilesystem(mfs, mountPoint)

	// Clear session on exit
	sessionMgr.ClearSession()
}

// serveFilesystem mounts and serves the filesystem
func serveFilesystem(mfs *mintfs.MintFS, mountPoint string) {
	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Run the filesystem (blocks until unmount)
	fmt.Printf("mintfs running. Read tokens from %s/<name>\n", mountPoint)
	fmt.Println("Press Ctrl+C to stop.")

	if err := mfs.Serve(ctx); err != nil {
		log.Fatalf("filesystem error: %v", err)
	}

	fmt.Println("Unmounted.")
}

// performFIDO2Assertion performs a FIDO2 assertion using the YubiKey
// This is a simplified implementation - in production, you'd use libfido2
func performFIDO2Assertion(challenge *client.AuthChallengeResponse, challengeBytes []byte) (*client.AuthVerifyRequest, error) {
	// For now, use the HMAC-SHA1 challenge-response as a simplified attestation
	// In a full implementation, you'd use libfido2 for proper FIDO2/WebAuthn assertions
	yk := attestation.NewYubiKey(2)
	response, err := yk.ChallengeResponse(challengeBytes)
	if err != nil {
		return nil, fmt.Errorf("YubiKey challenge-response failed: %w", err)
	}

	// Build a mock assertion for now
	// The server will need to be updated to handle this simplified auth
	// In production, this would be a proper FIDO2 assertion
	credentialID := ""
	if len(challenge.CredentialIDs) > 0 {
		credentialID = challenge.CredentialIDs[0]
	}

	// Build client data JSON
	clientData := map[string]interface{}{
		"type":      "webauthn.get",
		"challenge": challenge.Challenge,
		"origin":    "https://" + challenge.RPID,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	// Build authenticator data (simplified)
	// rpIdHash (32) + flags (1) + signCount (4) = 37 bytes minimum
	authData := make([]byte, 37)
	// Set flags byte (bit 0 = user present)
	authData[32] = 0x01

	return &client.AuthVerifyRequest{
		SessionID:         challenge.SessionID,
		CredentialID:      credentialID,
		AuthenticatorData: client.EncodeBytes(authData),
		ClientDataJSON:    client.EncodeBytes(clientDataJSON),
		Signature:         client.EncodeBytes(response),
		UserHandle:        challenge.UserID,
	}, nil
}

func stopCmd(args []string) {
	if len(args) == 0 {
		log.Fatal("usage: mintfs stop <mountpoint>")
	}

	mountPoint := args[0]

	// Expand ~ in path
	if len(mountPoint) > 1 && mountPoint[:2] == "~/" {
		home, _ := os.UserHomeDir()
		mountPoint = filepath.Join(home, mountPoint[2:])
	}

	// Unmount using fusermount
	if err := mintfs.Unmount(mountPoint); err != nil {
		log.Fatalf("failed to unmount: %v", err)
	}

	fmt.Printf("Unmounted %s\n", mountPoint)
}

func statusCmd(args []string) {
	mounts, err := mintfs.ListMounts()
	if err != nil {
		log.Fatalf("failed to list mounts: %v", err)
	}

	if len(mounts) == 0 {
		fmt.Println("No mintfs filesystems mounted.")
		return
	}

	fmt.Println("Mounted mintfs filesystems:")
	for _, m := range mounts {
		fmt.Printf("  %s\n", m)
	}
}
