package main

import (
	"context"
	"os"
	"strings"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/superfly/macaroon"
)

// MintFS is the FUSE filesystem that serves attenuated credentials
type MintFS struct {
	config *Config
}

var _ fs.FS = (*MintFS)(nil)

func (f *MintFS) Root() (fs.Node, error) {
	return &Dir{fs: f}, nil
}

// Dir represents the root directory containing credential files
type Dir struct {
	fs *MintFS
}

var _ fs.Node = (*Dir)(nil)
var _ fs.HandleReadDirAller = (*Dir)(nil)

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = 0o555 | os.ModeDir
	return nil
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	var entries []fuse.Dirent
	var inode uint64 = 2

	for name := range d.fs.config.Credentials {
		entries = append(entries, fuse.Dirent{
			Inode: inode,
			Name:  name,
			Type:  fuse.DT_File,
		})
		inode++
	}

	return entries, nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	cred, ok := d.fs.config.Credentials[name]
	if !ok {
		return nil, syscall.ENOENT
	}
	return &File{
		name:   name,
		config: cred,
	}, nil
}

// File represents a credential file that attenuates on read
type File struct {
	name   string
	config CredentialConfig
}

var _ fs.Node = (*File)(nil)
var _ fs.HandleReadAller = (*File)(nil)

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 2
	a.Mode = 0o444
	// Size is unknown until we generate the token
	a.Size = 4096 // estimate
	return nil
}

func (f *File) ReadAll(ctx context.Context) ([]byte, error) {
	token, err := attenuateToken(f.config)
	if err != nil {
		return nil, err
	}
	return []byte(token + "\n"), nil
}

// attenuateToken takes a base token and adds an expiry caveat
func attenuateToken(cfg CredentialConfig) (string, error) {
	// Decode the base token
	token := strings.TrimSpace(cfg.BaseToken)

	// Strip sk_ prefix and decode
	if !strings.HasPrefix(token, "sk_") {
		return "", syscall.EINVAL
	}

	m, err := decodeToken(token)
	if err != nil {
		return "", err
	}

	// Add expiry caveat
	now := time.Now()
	expiry := cfg.Expiry.Duration()
	if expiry == 0 {
		expiry = 5 * time.Minute // default 5 minute expiry
	}

	if err := m.Add(&macaroon.ValidityWindow{
		NotBefore: now.Unix(),
		NotAfter:  now.Add(expiry).Unix(),
	}); err != nil {
		return "", err
	}

	// Re-encode
	return encodeToken(m)
}
