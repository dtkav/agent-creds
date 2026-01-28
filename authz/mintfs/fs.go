package mintfs

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"authz/api/client"
	"authz/attestation"
	tfmac "authz/macaroon"
)

// MintFS is a FUSE filesystem that serves hot tokens from .akey files
type MintFS struct {
	mountPoint string
	akeyDir    string
	sessionMgr *attestation.SessionManager
	apiClient  *client.Client // For server-side mode
	sshHost    string         // For SSH mode (e.g., "authz.example.com" or "localhost:2222")
	server     *fuse.Server

	// Cache of loaded .akey files (local mode only)
	mu      sync.RWMutex
	entries map[string]string // name -> token string
}

// New creates a new MintFS instance (local mode with .akey files)
func New(mountPoint, akeyDir string, sessionMgr *attestation.SessionManager) (*MintFS, error) {
	mfs := &MintFS{
		mountPoint: mountPoint,
		akeyDir:    akeyDir,
		sessionMgr: sessionMgr,
		entries:    make(map[string]string),
	}

	// Load .akey files
	if err := mfs.loadAkeyFiles(); err != nil {
		return nil, fmt.Errorf("failed to load .akey files: %w", err)
	}

	return mfs, nil
}

// NewWithAPI creates a new MintFS instance (server mode with API client)
func NewWithAPI(mountPoint string, apiClient *client.Client) (*MintFS, error) {
	mfs := &MintFS{
		mountPoint: mountPoint,
		apiClient:  apiClient,
		entries:    make(map[string]string),
	}

	// Load token list from API
	if err := mfs.loadTokensFromAPI(); err != nil {
		return nil, fmt.Errorf("failed to load tokens from API: %w", err)
	}

	return mfs, nil
}

// NewWithSSH creates a new MintFS instance (SSH mode)
// sshHost is the SSH server to connect to (e.g., "authz.example.com" or "localhost -p 2222")
// hosts is the list of API hosts to expose as files
func NewWithSSH(mountPoint, sshHost string, hosts []string) (*MintFS, error) {
	mfs := &MintFS{
		mountPoint: mountPoint,
		sshHost:    sshHost,
		entries:    make(map[string]string),
	}

	// Create entries for each host
	for _, host := range hosts {
		// Use host as the filename (e.g., api.stripe.com)
		mfs.entries[host] = "" // Token will be fetched on demand
	}

	return mfs, nil
}

// IsSSHMode returns true if using SSH-based token minting
func (m *MintFS) IsSSHMode() bool {
	return m.sshHost != ""
}

// loadTokensFromAPI fetches the list of available tokens from the server
func (m *MintFS) loadTokensFromAPI() error {
	if m.apiClient == nil {
		return nil
	}

	tokens, err := m.apiClient.ListTokens()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, t := range tokens {
		// Store token ID as a marker - actual token fetched on read
		m.entries[t.ID] = ""
	}

	return nil
}

// IsServerMode returns true if using server-side token management
func (m *MintFS) IsServerMode() bool {
	return m.apiClient != nil
}

// loadAkeyFiles scans the akey directory and loads all .akey files
func (m *MintFS) loadAkeyFiles() error {
	entries, err := os.ReadDir(m.akeyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No akey directory is OK
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".akey") {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".akey")
		path := filepath.Join(m.akeyDir, entry.Name())

		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to read %s: %v\n", path, err)
			continue
		}

		token := strings.TrimSpace(string(content))
		if token == "" {
			continue
		}

		m.entries[name] = token
	}

	return nil
}

// Serve mounts and serves the filesystem
func (m *MintFS) Serve(ctx context.Context) error {
	root := &rootNode{mfs: m}

	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			Name:   "mintfs",
			FsName: "mintfs",
			Debug:  false,
		},
	}

	server, err := fs.Mount(m.mountPoint, root, opts)
	if err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}
	m.server = server

	// Wait for context cancellation or server exit
	go func() {
		<-ctx.Done()
		if err := Unmount(m.mountPoint); err != nil {
			fmt.Fprintf(os.Stderr, "unmount error: %v\n", err)
		}
	}()

	server.Wait()
	return nil
}

// Unmount unmounts a mintfs filesystem
func Unmount(mountPoint string) error {
	// Try fusermount first (Linux)
	if err := exec.Command("fusermount", "-u", mountPoint).Run(); err == nil {
		return nil
	}

	// Try umount (macOS/FreeBSD)
	if err := exec.Command("umount", mountPoint).Run(); err == nil {
		return nil
	}

	// Force unmount
	return syscall.Unmount(mountPoint, 0)
}

// ListMounts returns a list of mounted mintfs filesystems
func ListMounts() ([]string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		// Try mtab for non-Linux
		file, err = os.Open("/etc/mtab")
		if err != nil {
			return nil, err
		}
	}
	defer file.Close()

	var mounts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "mintfs") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				mounts = append(mounts, parts[1])
			}
		}
	}

	return mounts, scanner.Err()
}

// rootNode is the root of the mintfs filesystem
type rootNode struct {
	fs.Inode
	mfs *MintFS
}

var _ = (fs.NodeReaddirer)((*rootNode)(nil))
var _ = (fs.NodeLookuper)((*rootNode)(nil))

// Readdir lists available tokens
func (r *rootNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	r.mfs.mu.RLock()
	defer r.mfs.mu.RUnlock()

	entries := make([]fuse.DirEntry, 0, len(r.mfs.entries))
	var ino uint64 = 2
	for name := range r.mfs.entries {
		entries = append(entries, fuse.DirEntry{
			Name: name,
			Mode: fuse.S_IFREG | 0400,
			Ino:  ino,
		})
		ino++
	}

	return fs.NewListDirStream(entries), 0
}

// Lookup looks up a token by name
func (r *rootNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	r.mfs.mu.RLock()
	token, ok := r.mfs.entries[name]
	r.mfs.mu.RUnlock()

	if !ok {
		return nil, syscall.ENOENT
	}

	// Create token node
	child := &tokenNode{
		mfs:       r.mfs,
		name:      name,
		mainToken: token,
	}

	out.Mode = fuse.S_IFREG | 0400
	out.Size = uint64(len(token) + 200) // Approximate size with discharge

	stable := fs.StableAttr{
		Mode: fuse.S_IFREG | 0400,
		Ino:  0, // Let FUSE assign
	}
	return r.NewInode(ctx, child, stable), 0
}

// tokenNode represents a single token file
type tokenNode struct {
	fs.Inode
	mfs       *MintFS
	name      string
	mainToken string
}

var _ = (fs.NodeOpener)((*tokenNode)(nil))
var _ = (fs.NodeReader)((*tokenNode)(nil))
var _ = (fs.NodeGetattrer)((*tokenNode)(nil))

// Getattr returns file attributes
func (t *tokenNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = fuse.S_IFREG | 0400
	// Size will be set when opened
	out.Size = uint64(len(t.mainToken) + 200) // Approximate
	return 0
}

// Open opens the token file
func (t *tokenNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// Generate the hot token
	hotToken, err := t.generateHotToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate token for %s: %v\n", t.name, err)
		return nil, 0, syscall.EIO
	}

	return &tokenHandle{content: []byte(hotToken + "\n")}, fuse.FOPEN_DIRECT_IO, 0
}

// Read reads the token content
func (t *tokenNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	handle, ok := fh.(*tokenHandle)
	if !ok {
		return nil, syscall.EIO
	}

	if off >= int64(len(handle.content)) {
		return fuse.ReadResultData(nil), 0
	}

	end := off + int64(len(dest))
	if end > int64(len(handle.content)) {
		end = int64(len(handle.content))
	}

	return fuse.ReadResultData(handle.content[off:end]), 0
}

// generateHotToken creates a hot token from the main token
func (t *tokenNode) generateHotToken() (string, error) {
	// SSH mode: mint via SSH command
	if t.mfs.sshHost != "" {
		return t.mintViaSSH()
	}

	// Server mode: fetch from API
	if t.mfs.apiClient != nil {
		hotToken, err := t.mfs.apiClient.GetHotToken(t.name)
		if err != nil {
			return "", fmt.Errorf("failed to get token from server: %w", err)
		}
		return hotToken.Token, nil
	}

	// Local mode: generate discharge locally
	// Decode the main token
	m, err := tfmac.DecodeToken(t.mainToken)
	if err != nil {
		return "", fmt.Errorf("failed to decode token: %w", err)
	}

	// Check if it needs a discharge (has 3P caveat)
	caveats := m.UnsafeCaveats
	has3P := false
	for _, c := range caveats.Caveats {
		if c.Name() == "3P" { // Check for 3P caveat by name
			has3P = true
			break
		}
	}

	if !has3P {
		// No attestation required
		return t.mainToken, nil
	}

	// Create discharge using session
	discharge, err := t.mfs.sessionMgr.CreateDischarge(m)
	if err != nil {
		return "", fmt.Errorf("failed to create discharge: %w", err)
	}

	dischargeStr, err := attestation.EncodeDischarge(discharge)
	if err != nil {
		return "", fmt.Errorf("failed to encode discharge: %w", err)
	}

	return attestation.CombineTokens(t.mainToken, dischargeStr), nil
}

// mintViaSSH mints a token by calling the SSH server
func (t *tokenNode) mintViaSSH() (string, error) {
	// Parse SSH host (might include port like "localhost -p 2222")
	sshArgs := []string{}

	// Check if host includes port specification
	parts := strings.Fields(t.mfs.sshHost)
	if len(parts) > 1 {
		sshArgs = append(sshArgs, parts...)
	} else {
		sshArgs = append(sshArgs, t.mfs.sshHost)
	}

	// Add the mint command (t.name is the host like "api.stripe.com")
	sshArgs = append(sshArgs, "mint", t.name)

	cmd := exec.Command("ssh", sshArgs...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("ssh mint failed: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("ssh mint failed: %w", err)
	}

	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", fmt.Errorf("ssh mint returned empty token")
	}

	return token, nil
}

// tokenHandle holds the generated token content
type tokenHandle struct {
	content []byte
}

var _ = (fs.FileReader)((*tokenHandle)(nil))

func (h *tokenHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off >= int64(len(h.content)) {
		return fuse.ReadResultData(nil), 0
	}

	end := off + int64(len(dest))
	if end > int64(len(h.content)) {
		end = int64(len(h.content))
	}

	return fuse.ReadResultData(h.content[off:end]), 0
}
