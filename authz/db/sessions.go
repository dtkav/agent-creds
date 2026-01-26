package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"
)

// Session represents an authenticated session
type Session struct {
	ID        string
	UserID    []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

// DefaultSessionDuration is the default session lifetime
const DefaultSessionDuration = 1 * time.Hour

// CreateSession creates a new session for a user
func (d *DB) CreateSession(userID []byte, duration time.Duration) (*Session, error) {
	if duration == 0 {
		duration = DefaultSessionDuration
	}

	// Generate random session ID
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	now := time.Now()
	expiresAt := now.Add(duration)

	_, err := d.Exec(
		"INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		id, userID, now.Unix(), expiresAt.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}

// GetSession retrieves a session by ID (returns nil if expired or not found)
func (d *DB) GetSession(id string) (*Session, error) {
	var s Session
	var createdAt, expiresAt int64

	err := d.QueryRow(
		"SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = ?",
		id,
	).Scan(&s.ID, &s.UserID, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	s.CreatedAt = time.Unix(createdAt, 0)
	s.ExpiresAt = time.Unix(expiresAt, 0)

	// Check if expired
	if time.Now().After(s.ExpiresAt) {
		// Clean up expired session
		d.DeleteSession(id)
		return nil, nil
	}

	return &s, nil
}

// ValidateSession checks if a session is valid and returns the user ID
func (d *DB) ValidateSession(id string) ([]byte, error) {
	session, err := d.GetSession(id)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("invalid or expired session")
	}

	// Check that user is still active
	user, err := d.GetUser(session.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil || !user.Active {
		d.DeleteSession(id)
		return nil, fmt.Errorf("user not found or inactive")
	}

	return session.UserID, nil
}

// DeleteSession removes a session
func (d *DB) DeleteSession(id string) error {
	_, err := d.Exec("DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// DeleteSessionsForUser removes all sessions for a user
func (d *DB) DeleteSessionsForUser(userID []byte) error {
	_, err := d.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete sessions: %w", err)
	}
	return nil
}

// ExtendSession extends a session's expiration time
func (d *DB) ExtendSession(id string, duration time.Duration) error {
	newExpiry := time.Now().Add(duration).Unix()

	result, err := d.Exec(
		"UPDATE sessions SET expires_at = ? WHERE id = ?",
		newExpiry, id,
	)
	if err != nil {
		return fmt.Errorf("failed to extend session: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// WebAuthn challenge types
const (
	ChallengeTypeRegister     = "register"
	ChallengeTypeAuthenticate = "authenticate"
)

// WebAuthnChallenge represents a pending WebAuthn challenge
type WebAuthnChallenge struct {
	ID        string
	UserID    []byte
	Challenge []byte
	Type      string // "register" or "authenticate"
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateWebAuthnChallenge stores a new WebAuthn challenge
func (d *DB) CreateWebAuthnChallenge(id string, userID, challenge []byte, challengeType string, duration time.Duration) error {
	if duration == 0 {
		duration = 5 * time.Minute
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	_, err := d.Exec(
		`INSERT INTO webauthn_challenges (id, user_id, challenge, type, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, challenge, challengeType, now.Unix(), expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to create challenge: %w", err)
	}

	return nil
}

// GetWebAuthnChallenge retrieves and deletes a challenge (one-time use)
func (d *DB) GetWebAuthnChallenge(id string) (*WebAuthnChallenge, error) {
	var c WebAuthnChallenge
	var createdAt, expiresAt int64

	err := d.QueryRow(
		`SELECT id, user_id, challenge, type, created_at, expires_at
		 FROM webauthn_challenges WHERE id = ?`,
		id,
	).Scan(&c.ID, &c.UserID, &c.Challenge, &c.Type, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	// Delete the challenge (one-time use)
	d.Exec("DELETE FROM webauthn_challenges WHERE id = ?", id)

	c.CreatedAt = time.Unix(createdAt, 0)
	c.ExpiresAt = time.Unix(expiresAt, 0)

	// Check if expired
	if time.Now().After(c.ExpiresAt) {
		return nil, nil
	}

	return &c, nil
}

// DeleteWebAuthnChallenge removes a challenge
func (d *DB) DeleteWebAuthnChallenge(id string) error {
	_, err := d.Exec("DELETE FROM webauthn_challenges WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete challenge: %w", err)
	}
	return nil
}
