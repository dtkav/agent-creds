package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"vault/attestation"
	"vault/db"
	tfmac "vault/macaroon"

	"github.com/superfly/macaroon"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "user":
		userCmd(os.Args[2:])
	case "token":
		tokenCmd(os.Args[2:])
	case "acl":
		aclCmd(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`vault-admin - Admin CLI for authz service

Usage:
  vault-admin user <command>   Manage users
  vault-admin token <command>  Manage tokens
  vault-admin acl <command>    Manage token ACLs

User Commands:
  vault-admin user add <name> [--display-name <name>]
  vault-admin user list
  vault-admin user get <name>
  vault-admin user deactivate <name>
  vault-admin user activate <name>
  vault-admin user delete <name>

Token Commands:
  vault-admin token create <id> [options]
    --hosts <hosts>           Comma-separated list of allowed hosts
    --methods <methods>       Comma-separated list of HTTP methods
    --paths <patterns>        Comma-separated list of path patterns
    --valid-for <duration>    Token validity (default: 8760h = 1 year)
    --require-attestation     Require FIDO2 attestation
    --description <text>      Token description

  vault-admin token list
  vault-admin token get <id>
  vault-admin token delete <id>

ACL Commands:
  vault-admin acl grant <token-id> <username>
  vault-admin acl revoke <token-id> <username>
  vault-admin acl list <token-id>

Environment:
  AUTHZ_DB_PATH              Database path (default: /data/authz.db or ~/.config/agent-creds/authz.db)
  MACAROON_SIGNING_KEY       Base64-encoded signing key (for token creation)
  MACAROON_ENCRYPTION_KEY    Base64-encoded encryption key (for attestation tokens)
`)
}

func openDB() *db.DB {
	database, err := db.OpenDefault()
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	return database
}

// User commands
func userCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: vault-admin user <add|list|get|deactivate|activate|delete>")
		os.Exit(1)
	}

	switch args[0] {
	case "add":
		userAdd(args[1:])
	case "list":
		userList()
	case "get":
		userGet(args[1:])
	case "deactivate":
		userDeactivate(args[1:])
	case "activate":
		userActivate(args[1:])
	case "delete":
		userDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown user command: %s\n", args[0])
		os.Exit(1)
	}
}

func userAdd(args []string) {
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	displayName := fs.String("display-name", "", "Display name")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if fs.NArg() == 0 {
		log.Fatal("Usage: vault-admin user add <name> [--display-name <name>]")
	}

	name := fs.Arg(0)
	database := openDB()
	defer database.Close()

	user, err := database.CreateUser(name, *displayName)
	if err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}

	fmt.Printf("Created user: %s (ID: %s)\n", user.Name, hex.EncodeToString(user.ID))
}

func userList() {
	database := openDB()
	defer database.Close()

	users, err := database.ListUsers()
	if err != nil {
		log.Fatalf("Failed to list users: %v", err)
	}

	if len(users) == 0 {
		fmt.Println("No users found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tDISPLAY NAME\tACTIVE\tCREATED")
	for _, u := range users {
		active := "yes"
		if !u.Active {
			active = "no"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			hex.EncodeToString(u.ID)[:16]+"...",
			u.Name,
			u.DisplayName,
			active,
			u.CreatedAt.Format(time.RFC3339),
		)
	}
	w.Flush()
}

func userGet(args []string) {
	if len(args) == 0 {
		log.Fatal("Usage: vault-admin user get <name>")
	}

	database := openDB()
	defer database.Close()

	user, err := database.GetUserByName(args[0])
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		log.Fatalf("User not found: %s", args[0])
	}

	fmt.Printf("ID:           %s\n", hex.EncodeToString(user.ID))
	fmt.Printf("Name:         %s\n", user.Name)
	fmt.Printf("Display Name: %s\n", user.DisplayName)
	fmt.Printf("Active:       %v\n", user.Active)
	fmt.Printf("Created:      %s\n", user.CreatedAt.Format(time.RFC3339))

	// Show credentials
	creds, _ := database.GetCredentialsByUser(user.ID)
	if len(creds) > 0 {
		fmt.Printf("\nCredentials: %d\n", len(creds))
		for i, c := range creds {
			lastUsed := "never"
			if c.LastUsed != nil {
				lastUsed = c.LastUsed.Format(time.RFC3339)
			}
			fmt.Printf("  %d. %s... (sign count: %d, last used: %s)\n",
				i+1, hex.EncodeToString(c.ID)[:16], c.SignCount, lastUsed)
		}
	}

	// Show accessible tokens
	tokens, _ := database.ListTokensForUser(user.ID)
	if len(tokens) > 0 {
		fmt.Printf("\nAccessible Tokens: %d\n", len(tokens))
		for _, t := range tokens {
			fmt.Printf("  - %s\n", t.ID)
		}
	}
}

func userDeactivate(args []string) {
	if len(args) == 0 {
		log.Fatal("Usage: vault-admin user deactivate <name>")
	}

	database := openDB()
	defer database.Close()

	user, err := database.GetUserByName(args[0])
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		log.Fatalf("User not found: %s", args[0])
	}

	if err := database.DeactivateUser(user.ID); err != nil {
		log.Fatalf("Failed to deactivate user: %v", err)
	}

	fmt.Printf("Deactivated user: %s\n", user.Name)
}

func userActivate(args []string) {
	if len(args) == 0 {
		log.Fatal("Usage: vault-admin user activate <name>")
	}

	database := openDB()
	defer database.Close()

	user, err := database.GetUserByName(args[0])
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		log.Fatalf("User not found: %s", args[0])
	}

	if err := database.ActivateUser(user.ID); err != nil {
		log.Fatalf("Failed to activate user: %v", err)
	}

	fmt.Printf("Activated user: %s\n", user.Name)
}

func userDelete(args []string) {
	if len(args) == 0 {
		log.Fatal("Usage: vault-admin user delete <name>")
	}

	database := openDB()
	defer database.Close()

	user, err := database.GetUserByName(args[0])
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		log.Fatalf("User not found: %s", args[0])
	}

	if err := database.DeleteUser(user.ID); err != nil {
		log.Fatalf("Failed to delete user: %v", err)
	}

	fmt.Printf("Deleted user: %s\n", user.Name)
}

// Token commands
func tokenCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: vault-admin token <create|list|get|delete>")
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		tokenCreate(args[1:])
	case "list":
		tokenList()
	case "get":
		tokenGet(args[1:])
	case "delete":
		tokenDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown token command: %s\n", args[0])
		os.Exit(1)
	}
}

func tokenCreate(args []string) {
	fs := flag.NewFlagSet("token create", flag.ExitOnError)
	hosts := fs.String("hosts", "", "Comma-separated list of allowed hosts")
	methods := fs.String("methods", "", "Comma-separated list of HTTP methods")
	paths := fs.String("paths", "", "Comma-separated list of path patterns")
	validFor := fs.Duration("valid-for", 8760*time.Hour, "Token validity duration")
	requireAttestation := fs.Bool("require-attestation", false, "Require FIDO2 attestation")
	description := fs.String("description", "", "Token description")

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	if fs.NArg() == 0 {
		log.Fatal("Usage: vault-admin token create <id> [options]")
	}

	tokenID := fs.Arg(0)

	// Load key store
	keyStore, err := tfmac.LoadKeyStore()
	if err != nil {
		log.Fatalf("Failed to load keys: %v", err)
	}

	// Create the macaroon
	m, err := keyStore.NewToken()
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	// Add validity window
	now := time.Now()
	if err := m.Add(&macaroon.ValidityWindow{
		NotBefore: now.Unix(),
		NotAfter:  now.Add(*validFor).Unix(),
	}); err != nil {
		log.Fatalf("Failed to add validity: %v", err)
	}

	// Add caveats
	if *hosts != "" {
		hostList := splitAndTrim(*hosts)
		if err := m.Add(&tfmac.HostCaveat{Hosts: hostList}); err != nil {
			log.Fatalf("Failed to add host caveat: %v", err)
		}
	}

	if *methods != "" {
		methodList := splitAndTrim(*methods)
		for i := range methodList {
			methodList[i] = strings.ToUpper(methodList[i])
		}
		if err := m.Add(&tfmac.MethodCaveat{Methods: methodList}); err != nil {
			log.Fatalf("Failed to add method caveat: %v", err)
		}
	}

	if *paths != "" {
		pathList := splitAndTrim(*paths)
		if err := m.Add(&tfmac.PathCaveat{Patterns: pathList}); err != nil {
			log.Fatalf("Failed to add path caveat: %v", err)
		}
	}

	if *requireAttestation {
		if len(keyStore.EncryptionKey) == 0 {
			log.Fatal("MACAROON_ENCRYPTION_KEY required for attestation")
		}
		if err := attestation.Add3PCaveat(m, keyStore.EncryptionKey); err != nil {
			log.Fatalf("Failed to add attestation caveat: %v", err)
		}
	}

	// Encode token
	tokenStr, err := tfmac.EncodeToken(m)
	if err != nil {
		log.Fatalf("Failed to encode token: %v", err)
	}

	// Store in database
	database := openDB()
	defer database.Close()

	token := &db.Token{
		ID:          tokenID,
		Macaroon:    tokenStr,
		Description: *description,
	}

	if err := database.CreateToken(token); err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("Created token: %s\n", tokenID)
	fmt.Printf("  Hosts:       %s\n", *hosts)
	fmt.Printf("  Methods:     %s\n", *methods)
	fmt.Printf("  Paths:       %s\n", *paths)
	fmt.Printf("  Valid until: %s\n", now.Add(*validFor).Format(time.RFC3339))
	fmt.Printf("  Attestation: %v\n", *requireAttestation)
}

func tokenList() {
	database := openDB()
	defer database.Close()

	tokens, err := database.ListTokens()
	if err != nil {
		log.Fatalf("Failed to list tokens: %v", err)
	}

	if len(tokens) == 0 {
		fmt.Println("No tokens found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tDESCRIPTION\tCREATED")
	for _, t := range tokens {
		fmt.Fprintf(w, "%s\t%s\t%s\n",
			t.ID,
			truncate(t.Description, 40),
			t.CreatedAt.Format(time.RFC3339),
		)
	}
	w.Flush()
}

func tokenGet(args []string) {
	if len(args) == 0 {
		log.Fatal("Usage: vault-admin token get <id>")
	}

	database := openDB()
	defer database.Close()

	token, err := database.GetToken(args[0])
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}
	if token == nil {
		log.Fatalf("Token not found: %s", args[0])
	}

	fmt.Printf("ID:          %s\n", token.ID)
	fmt.Printf("Description: %s\n", token.Description)
	fmt.Printf("Created:     %s\n", token.CreatedAt.Format(time.RFC3339))

	// Decode and show caveats
	m, err := tfmac.DecodeToken(token.Macaroon)
	if err == nil {
		fmt.Println("\nCaveats:")
		for _, c := range m.UnsafeCaveats.Caveats {
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
			}
		}
	}

	// Show ACLs
	acls, _ := database.ListTokenACLs(token.ID)
	if len(acls) > 0 {
		fmt.Printf("\nACLs: %d users\n", len(acls))
		for _, a := range acls {
			user, _ := database.GetUser(a.UserID)
			username := hex.EncodeToString(a.UserID)[:16] + "..."
			if user != nil {
				username = user.Name
			}
			fmt.Printf("  - %s (granted: %s)\n", username, a.GrantedAt.Format(time.RFC3339))
		}
	}
}

func tokenDelete(args []string) {
	if len(args) == 0 {
		log.Fatal("Usage: vault-admin token delete <id>")
	}

	database := openDB()
	defer database.Close()

	if err := database.DeleteToken(args[0]); err != nil {
		log.Fatalf("Failed to delete token: %v", err)
	}

	fmt.Printf("Deleted token: %s\n", args[0])
}

// ACL commands
func aclCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: vault-admin acl <grant|revoke|list>")
		os.Exit(1)
	}

	switch args[0] {
	case "grant":
		aclGrant(args[1:])
	case "revoke":
		aclRevoke(args[1:])
	case "list":
		aclList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown acl command: %s\n", args[0])
		os.Exit(1)
	}
}

func aclGrant(args []string) {
	if len(args) < 2 {
		log.Fatal("Usage: vault-admin acl grant <token-id> <username>")
	}

	tokenID := args[0]
	username := args[1]

	database := openDB()
	defer database.Close()

	// Get user
	user, err := database.GetUserByName(username)
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		log.Fatalf("User not found: %s", username)
	}

	// Grant access
	if err := database.GrantTokenAccess(tokenID, user.ID, nil); err != nil {
		log.Fatalf("Failed to grant access: %v", err)
	}

	fmt.Printf("Granted access to %s for user %s\n", tokenID, username)
}

func aclRevoke(args []string) {
	if len(args) < 2 {
		log.Fatal("Usage: vault-admin acl revoke <token-id> <username>")
	}

	tokenID := args[0]
	username := args[1]

	database := openDB()
	defer database.Close()

	// Get user
	user, err := database.GetUserByName(username)
	if err != nil {
		log.Fatalf("Failed to get user: %v", err)
	}
	if user == nil {
		log.Fatalf("User not found: %s", username)
	}

	// Revoke access
	if err := database.RevokeTokenAccess(tokenID, user.ID); err != nil {
		log.Fatalf("Failed to revoke access: %v", err)
	}

	fmt.Printf("Revoked access to %s for user %s\n", tokenID, username)
}

func aclList(args []string) {
	if len(args) == 0 {
		log.Fatal("Usage: vault-admin acl list <token-id>")
	}

	tokenID := args[0]

	database := openDB()
	defer database.Close()

	acls, err := database.ListTokenACLs(tokenID)
	if err != nil {
		log.Fatalf("Failed to list ACLs: %v", err)
	}

	if len(acls) == 0 {
		fmt.Printf("No ACLs for token: %s\n", tokenID)
		return
	}

	fmt.Printf("ACLs for token %s:\n", tokenID)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tGRANTED AT")
	for _, a := range acls {
		user, _ := database.GetUser(a.UserID)
		username := hex.EncodeToString(a.UserID)[:16] + "..."
		if user != nil {
			username = user.Name
		}
		fmt.Fprintf(w, "%s\t%s\n", username, a.GrantedAt.Format(time.RFC3339))
	}
	w.Flush()
}

// Helpers
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
