package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/bubbletea"
	"github.com/superfly/macaroon"
	gossh "golang.org/x/crypto/ssh"

	"vault/db"
	tfmac "vault/macaroon"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D7FF")).
			MarginBottom(1)

	statusApproved = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#02BF87")).
			Render("● approved")

	statusPending = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFCC00")).
			Render("○ pending")

	statusAdmin = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5FD7")).
			Render("★ admin")

	subtleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5555"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#02BF87"))
)

// User status constants
const (
	UserStatusPending  = "pending"
	UserStatusApproved = "approved"
	UserStatusAdmin    = "admin"
)

// Global resources (initialized in main)
var (
	database *db.DB
	keyStore *tfmac.KeyStore
)

// configuredHosts lists hosts that can be minted (loaded from domains_gen.go if available)
// For now, we'll allow any host - in production this should be restricted
var configuredHosts = []string{
	"api.stripe.com",
	"api.openai.com",
	"api.anthropic.com",
	"api.github.com",
}

// ============================================================================
// Direct Commands (non-TUI)
// ============================================================================

func handleCommand(sess ssh.Session, userID []byte, fingerprint, status string, args []string) {
	if len(args) == 0 {
		return // No command, will fall through to TUI
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "help":
		cmdHelp(sess)
	case "whoami":
		cmdWhoami(sess, fingerprint, status)
	case "mint":
		cmdMint(sess, userID, status, cmdArgs)
	case "keys":
		cmdKeys(sess, userID, cmdArgs)
	case "users":
		cmdUsers(sess, status, cmdArgs)
	default:
		fmt.Fprintf(sess, "Unknown command: %s\n", cmd)
		fmt.Fprintf(sess, "Run 'help' for available commands.\n")
	}
}

func cmdHelp(sess ssh.Session) {
	help := `agent-creds SSH interface

Commands:
  help              Show this help
  whoami            Show your identity and status
  mint <host>       Mint a token for the given host
    --methods       Restrict HTTP methods (e.g., GET,POST)
    --paths         Restrict paths (e.g., /v1/*)
    --valid-for     Token validity (e.g., 1h, 24h)
  keys              List your SSH keys
  keys add          Add a new SSH key (paste pubkey)
  users             List users (admin only)
  users approve <fingerprint>  Approve a pending user (admin only)

Without a command, opens the interactive TUI.
`
	fmt.Fprint(sess, help)
}

func cmdWhoami(sess ssh.Session, fingerprint, status string) {
	fmt.Fprintf(sess, "User: %s\n", sess.User())
	fmt.Fprintf(sess, "Fingerprint: %s\n", fingerprint)
	fmt.Fprintf(sess, "Status: %s\n", status)
}

func cmdMint(sess ssh.Session, userID []byte, status string, args []string) {
	if status == UserStatusPending {
		fmt.Fprintln(sess, "Error: Your account is pending approval.")
		return
	}

	if len(args) == 0 {
		fmt.Fprintln(sess, "Usage: mint <host> [--methods GET,POST] [--paths /v1/*] [--valid-for 1h]")
		fmt.Fprintln(sess, "\nConfigured hosts:")
		for _, host := range configuredHosts {
			fmt.Fprintf(sess, "  %s\n", host)
		}
		return
	}

	host := args[0]

	// Parse optional flags
	var methods, paths []string
	validFor := 24 * time.Hour

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--methods":
			if i+1 < len(args) {
				methods = strings.Split(args[i+1], ",")
				i++
			}
		case "--paths":
			if i+1 < len(args) {
				paths = strings.Split(args[i+1], ",")
				i++
			}
		case "--valid-for":
			if i+1 < len(args) {
				d, err := time.ParseDuration(args[i+1])
				if err != nil {
					fmt.Fprintf(sess, "Error: Invalid duration '%s'\n", args[i+1])
					return
				}
				validFor = d
				i++
			}
		}
	}

	// Create token
	m, err := keyStore.NewToken()
	if err != nil {
		fmt.Fprintf(sess, "Error creating token: %v\n", err)
		return
	}

	// Add validity window
	now := time.Now()
	if err := m.Add(&macaroon.ValidityWindow{
		NotBefore: now.Unix(),
		NotAfter:  now.Add(validFor).Unix(),
	}); err != nil {
		fmt.Fprintf(sess, "Error adding validity: %v\n", err)
		return
	}

	// Always restrict to the requested host
	if err := m.Add(&tfmac.HostCaveat{Hosts: []string{host}}); err != nil {
		fmt.Fprintf(sess, "Error adding host caveat: %v\n", err)
		return
	}

	if len(methods) > 0 {
		if err := m.Add(&tfmac.MethodCaveat{Methods: methods}); err != nil {
			fmt.Fprintf(sess, "Error adding method caveat: %v\n", err)
			return
		}
	}

	if len(paths) > 0 {
		if err := m.Add(&tfmac.PathCaveat{Patterns: paths}); err != nil {
			fmt.Fprintf(sess, "Error adding path caveat: %v\n", err)
			return
		}
	}

	// Encode token
	token, err := tfmac.EncodeToken(m)
	if err != nil {
		fmt.Fprintf(sess, "Error encoding token: %v\n", err)
		return
	}

	fmt.Fprintln(sess, token)
}

func cmdKeys(sess ssh.Session, userID []byte, args []string) {
	if len(args) > 0 && args[0] == "add" {
		// Read pubkey from stdin
		fmt.Fprintln(sess, "Paste your SSH public key (then press Enter):")
		pubkey, err := io.ReadAll(sess)
		if err != nil {
			fmt.Fprintf(sess, "Error reading key: %v\n", err)
			return
		}

		// Parse to get fingerprint
		pk, _, _, _, err := gossh.ParseAuthorizedKey(pubkey)
		if err != nil {
			fmt.Fprintf(sess, "Error parsing key: %v\n", err)
			return
		}

		fingerprint := gossh.FingerprintSHA256(pk)

		// Add to database
		if err := database.AddSSHKey(userID, fingerprint, ""); err != nil {
			fmt.Fprintf(sess, "Error adding key: %v\n", err)
			return
		}

		fmt.Fprintf(sess, "Added key: %s\n", fingerprint)
		return
	}

	// List keys
	keys, err := database.ListSSHKeys(userID)
	if err != nil {
		fmt.Fprintf(sess, "Error listing keys: %v\n", err)
		return
	}

	if len(keys) == 0 {
		fmt.Fprintln(sess, "No SSH keys registered.")
		return
	}

	fmt.Fprintln(sess, "Your SSH keys:")
	for _, k := range keys {
		fmt.Fprintf(sess, "  %s\n", k)
	}
}

func cmdUsers(sess ssh.Session, status string, args []string) {
	if status != UserStatusAdmin {
		fmt.Fprintln(sess, "Error: Admin access required.")
		return
	}

	if len(args) > 0 && args[0] == "approve" {
		if len(args) < 2 {
			fmt.Fprintln(sess, "Usage: users approve <fingerprint>")
			return
		}

		fingerprint := args[1]

		// Find user by fingerprint
		userID, userStatus, err := database.GetUserByFingerprint(fingerprint)
		if err != nil {
			fmt.Fprintf(sess, "Error: User not found with fingerprint %s\n", fingerprint)
			return
		}

		if userStatus != UserStatusPending {
			fmt.Fprintf(sess, "User is already %s\n", userStatus)
			return
		}

		if err := database.ApproveUser(userID); err != nil {
			fmt.Fprintf(sess, "Error approving user: %v\n", err)
			return
		}

		fmt.Fprintf(sess, "Approved user: %s\n", fingerprint)
		return
	}

	// List all users
	users, err := database.ListUsers()
	if err != nil {
		fmt.Fprintf(sess, "Error listing users: %v\n", err)
		return
	}

	pending, err := database.ListPendingUsers()
	if err != nil {
		fmt.Fprintf(sess, "Error listing pending users: %v\n", err)
		return
	}

	if len(pending) > 0 {
		fmt.Fprintln(sess, "Pending approval:")
		for _, u := range pending {
			fmt.Fprintf(sess, "  %s (joined %s)\n", u.Fingerprint, u.CreatedAt.Format("2006-01-02"))
		}
		fmt.Fprintln(sess)
	}

	fmt.Fprintln(sess, "All users:")
	for _, u := range users {
		status := "approved"
		// We'd need to add status to User struct, for now just show the list
		fmt.Fprintf(sess, "  %s (%s)\n", u.Name, status)
	}
}

// ============================================================================
// TUI Mode
// ============================================================================

// pendingUser is a list item for the approval list
type pendingUser struct {
	id          []byte
	fingerprint string
	createdAt   time.Time
}

func (p pendingUser) Title() string       { return p.fingerprint }
func (p pendingUser) Description() string { return "joined " + p.createdAt.Format("2006-01-02 15:04") }
func (p pendingUser) FilterValue() string { return p.fingerprint }

// hostItem is a list item for the mint host selection
type hostItem struct {
	host string
}

func (h hostItem) Title() string       { return h.host }
func (h hostItem) Description() string { return "" }
func (h hostItem) FilterValue() string { return h.host }

// view represents which screen we're on
type view int

const (
	viewMain view = iota
	viewPendingUsers
	viewMintSelect
	viewMintResult
)

// model is the bubbletea model for the TUI
type model struct {
	userID      []byte
	fingerprint string
	status      string
	width       int
	height      int

	currentView view
	message     string

	// For admin approval view
	pendingList list.Model

	// For minting
	hostList    list.Model
	mintedToken string
}

func initialModel(userID []byte, fingerprint, status string) model {
	// Set up the pending users list
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	pendingList := list.New([]list.Item{}, delegate, 0, 0)
	pendingList.Title = "Pending Users"
	pendingList.SetShowHelp(false)
	pendingList.SetShowStatusBar(false)

	// Set up the host list for minting
	var hostItems []list.Item
	for _, host := range configuredHosts {
		hostItems = append(hostItems, hostItem{host: host})
	}
	hostList := list.New(hostItems, delegate, 0, 0)
	hostList.Title = "Select Host"
	hostList.SetShowHelp(false)
	hostList.SetShowStatusBar(false)

	return model{
		userID:      userID,
		fingerprint: fingerprint,
		status:      status,
		pendingList: pendingList,
		hostList:    hostList,
		currentView: viewMain,
	}
}

func (m model) Init() tea.Cmd {
	if m.status == UserStatusAdmin {
		return m.loadPendingUsers
	}
	return nil
}

type pendingUsersMsg []list.Item
type approvalResultMsg struct {
	success     bool
	fingerprint string
	err         error
}
type mintResultMsg struct {
	token string
	err   error
}

func (m model) loadPendingUsers() tea.Msg {
	users, err := database.ListPendingUsers()
	if err != nil {
		return pendingUsersMsg{}
	}

	items := make([]list.Item, 0, len(users))
	for _, u := range users {
		items = append(items, pendingUser{
			id:          u.ID,
			fingerprint: u.Fingerprint,
			createdAt:   u.CreatedAt,
		})
	}
	return pendingUsersMsg(items)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			if m.currentView == viewMain {
				return m, tea.Quit
			}
			// Go back to main view
			m.currentView = viewMain
			m.message = ""
			return m, nil

		case "esc":
			m.currentView = viewMain
			m.message = ""
			return m, nil

		case "p":
			// Show pending users (admin only)
			if m.status == UserStatusAdmin && m.currentView == viewMain {
				m.currentView = viewPendingUsers
				return m, m.loadPendingUsers
			}

		case "m":
			// Mint token (approved users)
			if m.status != UserStatusPending && m.currentView == viewMain {
				m.currentView = viewMintSelect
				return m, nil
			}

		case "enter":
			switch m.currentView {
			case viewPendingUsers:
				// Approve selected user
				if item, ok := m.pendingList.SelectedItem().(pendingUser); ok {
					return m, m.approveUser(item.id, item.fingerprint)
				}
			case viewMintSelect:
				// Mint token for selected host
				if item, ok := m.hostList.SelectedItem().(hostItem); ok {
					return m, m.mintToken(item.host)
				}
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.pendingList.SetSize(msg.Width-4, msg.Height-8)
		m.hostList.SetSize(msg.Width-4, msg.Height-8)

	case pendingUsersMsg:
		m.pendingList.SetItems([]list.Item(msg))

	case approvalResultMsg:
		if msg.success {
			m.message = successStyle.Render(fmt.Sprintf("✓ Approved %s", msg.fingerprint))
			return m, m.loadPendingUsers
		} else {
			m.message = errorStyle.Render("Error: " + msg.err.Error())
		}

	case mintResultMsg:
		if msg.err != nil {
			m.message = errorStyle.Render("Error: " + msg.err.Error())
			m.currentView = viewMain
		} else {
			m.mintedToken = msg.token
			m.currentView = viewMintResult
		}
	}

	// Update the active list
	var cmd tea.Cmd
	switch m.currentView {
	case viewPendingUsers:
		m.pendingList, cmd = m.pendingList.Update(msg)
	case viewMintSelect:
		m.hostList, cmd = m.hostList.Update(msg)
	}

	return m, cmd
}

func (m model) approveUser(userID []byte, fingerprint string) tea.Cmd {
	return func() tea.Msg {
		err := database.ApproveUser(userID)
		return approvalResultMsg{success: err == nil, fingerprint: fingerprint, err: err}
	}
}

func (m model) mintToken(host string) tea.Cmd {
	return func() tea.Msg {
		// Create token
		mac, err := keyStore.NewToken()
		if err != nil {
			return mintResultMsg{err: err}
		}

		// Add validity window (24 hours)
		now := time.Now()
		if err := mac.Add(&macaroon.ValidityWindow{
			NotBefore: now.Unix(),
			NotAfter:  now.Add(24 * time.Hour).Unix(),
		}); err != nil {
			return mintResultMsg{err: err}
		}

		// Add host restriction
		if err := mac.Add(&tfmac.HostCaveat{Hosts: []string{host}}); err != nil {
			return mintResultMsg{err: err}
		}

		// Encode token
		token, err := tfmac.EncodeToken(mac)
		if err != nil {
			return mintResultMsg{err: err}
		}

		return mintResultMsg{token: token}
	}
}

func (m model) View() string {
	var b strings.Builder

	// Header
	b.WriteString(titleStyle.Render("agent-creds"))
	b.WriteString("\n")

	// User info
	b.WriteString(fmt.Sprintf("Key: %s\n", subtleStyle.Render(m.fingerprint)))

	switch m.status {
	case UserStatusAdmin:
		b.WriteString(fmt.Sprintf("Status: %s\n\n", statusAdmin))
	case UserStatusApproved:
		b.WriteString(fmt.Sprintf("Status: %s\n\n", statusApproved))
	case UserStatusPending:
		b.WriteString(fmt.Sprintf("Status: %s\n\n", statusPending))
	}

	// View-specific content
	switch m.currentView {
	case viewMain:
		b.WriteString(m.viewMain())
	case viewPendingUsers:
		b.WriteString(m.pendingList.View())
		b.WriteString("\n\n")
		b.WriteString(subtleStyle.Render("enter: approve • esc: back • q: quit"))
	case viewMintSelect:
		b.WriteString(m.hostList.View())
		b.WriteString("\n\n")
		b.WriteString(subtleStyle.Render("enter: mint • esc: back • q: quit"))
	case viewMintResult:
		b.WriteString("Token minted successfully!\n\n")
		b.WriteString(m.mintedToken)
		b.WriteString("\n\n")
		b.WriteString(subtleStyle.Render("esc: back • q: quit"))
	}

	if m.message != "" && m.currentView != viewMintResult {
		b.WriteString("\n\n" + m.message)
	}

	return b.String()
}

func (m model) viewMain() string {
	var b strings.Builder

	switch m.status {
	case UserStatusPending:
		b.WriteString("Your account is pending approval.\n")
		b.WriteString("An admin will review your request.\n\n")
		b.WriteString(subtleStyle.Render("q: quit"))

	case UserStatusApproved:
		b.WriteString("You can mint tokens for configured APIs.\n\n")
		b.WriteString(subtleStyle.Render("m: mint token • q: quit"))

	case UserStatusAdmin:
		b.WriteString("You have full admin access.\n\n")
		b.WriteString(subtleStyle.Render("m: mint token • p: pending users • q: quit"))
	}

	return b.String()
}

// ============================================================================
// Main
// ============================================================================

func main() {
	var err error

	// Open database
	database, err = db.OpenDefault()
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Load keystore
	keyStore, err = tfmac.LoadKeyStore()
	if err != nil {
		log.Fatalf("Failed to load keystore: %v", err)
	}

	host := os.Getenv("SSH_HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	port := os.Getenv("SSH_PORT")
	if port == "" {
		port = "2222"
	}

	hostKeyPath := os.Getenv("SSH_HOST_KEY")
	if hostKeyPath == "" {
		hostKeyPath = "vault_host_key"
	}

	srv, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort(host, port)),
		wish.WithHostKeyPath(hostKeyPath),
		wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			// Accept all keys - we'll create/lookup user in the handler
			return true
		}),
		wish.WithMiddleware(
			bubbletea.Middleware(func(sess ssh.Session) (tea.Model, []tea.ProgramOption) {
				fingerprint := gossh.FingerprintSHA256(sess.PublicKey())

				// Look up user (should exist from middleware above)
				userID, status, _ := database.GetUserByFingerprint(fingerprint)

				pty, _, _ := sess.Pty()
				m := initialModel(userID, fingerprint, status)
				m.width = pty.Window.Width
				m.height = pty.Window.Height

				return m, []tea.ProgramOption{tea.WithAltScreen()}
			}),
			func(next ssh.Handler) ssh.Handler {
				return func(sess ssh.Session) {
					fingerprint := gossh.FingerprintSHA256(sess.PublicKey())

					// Look up or create user
					userID, status, err := getOrCreateUser(fingerprint, sess.User())
					if err != nil {
						log.Printf("Failed to get/create user: %v", err)
						fmt.Fprintf(sess, "Error: %v\n", err)
						return
					}

					// Check if this is a direct command
					cmd := sess.Command()
					if len(cmd) > 0 {
						handleCommand(sess, userID, fingerprint, status, cmd)
						return
					}

					// Fall through to TUI
					next(sess)
				}
			},
		),
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	log.Printf("Starting SSH server on %s:%s", host, port)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-done
	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
}

func getOrCreateUser(fingerprint, sshUser string) ([]byte, string, error) {
	// Try to find existing user by fingerprint
	userID, status, err := database.GetUserByFingerprint(fingerprint)
	if err == nil {
		return userID, status, nil
	}

	// Check if this is the first user (becomes admin)
	isFirst, err := database.IsFirstUser()
	if err != nil {
		return nil, "", fmt.Errorf("failed to check first user: %w", err)
	}

	initialStatus := UserStatusPending
	if isFirst {
		initialStatus = UserStatusAdmin
		log.Printf("First user %s (%s) -> admin", fingerprint, sshUser)
	} else {
		log.Printf("New user %s (%s) -> pending", fingerprint, sshUser)
	}

	// Create user with SSH username as display name
	userID, err = database.CreateUserWithFingerprint(fingerprint, initialStatus, sshUser)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	return userID, initialStatus, nil
}
