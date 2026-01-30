package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite database connection
type DB struct {
	*sql.DB
}

// Open opens or creates the database at the given path
func Open(path string) (*DB, error) {
	// Create parent directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	d := &DB{DB: db}

	// Run migrations
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return d, nil
}

// OpenDefault opens the database at the default location
func OpenDefault() (*DB, error) {
	path := os.Getenv("AUTHZ_DB_PATH")
	if path == "" {
		// Default to /data/authz.db for container, or ~/.config/agent-creds/authz.db for local
		if _, err := os.Stat("/data"); err == nil {
			path = "/data/authz.db"
		} else {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, ".config", "agent-creds", "authz.db")
		}
	}
	return Open(path)
}

// migrate runs all database migrations
func (d *DB) migrate() error {
	migrations := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id BLOB PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT,
			created_at INTEGER NOT NULL,
			active INTEGER DEFAULT 1
		)`,

		// FIDO2 credentials (multiple per user)
		`CREATE TABLE IF NOT EXISTS credentials (
			id BLOB PRIMARY KEY,
			user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			public_key BLOB NOT NULL,
			sign_count INTEGER DEFAULT 0,
			aaguid BLOB,
			created_at INTEGER NOT NULL,
			last_used INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id)`,

		// Tokens (.akey content stored server-side)
		`CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			macaroon TEXT NOT NULL,
			description TEXT,
			created_at INTEGER NOT NULL,
			created_by BLOB REFERENCES users(id)
		)`,

		// Token ACLs (which users can access which tokens)
		`CREATE TABLE IF NOT EXISTS token_acls (
			token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
			user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			granted_at INTEGER NOT NULL,
			granted_by BLOB REFERENCES users(id),
			PRIMARY KEY (token_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_token_acls_user ON token_acls(user_id)`,

		// Sessions (for authenticated CLI/web sessions)
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`,

		// WebAuthn challenges (temporary, for registration/authentication flow)
		`CREATE TABLE IF NOT EXISTS webauthn_challenges (
			id TEXT PRIMARY KEY,
			user_id BLOB REFERENCES users(id),
			challenge BLOB NOT NULL,
			type TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,

		// SSH keys (for SSH-based authentication)
		`CREATE TABLE IF NOT EXISTS ssh_keys (
			fingerprint TEXT PRIMARY KEY,
			user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			comment TEXT,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ssh_keys_user ON ssh_keys(user_id)`,

		// Add status column to users if it doesn't exist
		`ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'pending'`,
	}

	for _, m := range migrations {
		_, err := d.Exec(m)
		if err != nil {
			// Ignore "duplicate column" errors from ALTER TABLE
			if strings.Contains(err.Error(), "duplicate column") {
				continue
			}
			return fmt.Errorf("migration failed: %w\nSQL: %s", err, m)
		}
	}

	return nil
}

// CleanupExpired removes expired sessions and challenges
func (d *DB) CleanupExpired() error {
	now := unixNow()

	if _, err := d.Exec("DELETE FROM sessions WHERE expires_at < ?", now); err != nil {
		return fmt.Errorf("failed to cleanup sessions: %w", err)
	}

	if _, err := d.Exec("DELETE FROM webauthn_challenges WHERE expires_at < ?", now); err != nil {
		return fmt.Errorf("failed to cleanup challenges: %w", err)
	}

	return nil
}
