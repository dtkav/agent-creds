package db

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"
)

// User represents a user in the system
type User struct {
	ID          []byte
	Name        string
	DisplayName string
	CreatedAt   time.Time
	Active      bool
}

// CreateUser creates a new user with a random ID
func (d *DB) CreateUser(name, displayName string) (*User, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	now := unixNow()

	_, err := d.Exec(
		"INSERT INTO users (id, name, display_name, created_at, active) VALUES (?, ?, ?, ?, 1)",
		id, name, displayName, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &User{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
		CreatedAt:   time.Unix(now, 0),
		Active:      true,
	}, nil
}

// GetUser retrieves a user by ID
func (d *DB) GetUser(id []byte) (*User, error) {
	var u User
	var createdAt int64
	var active int

	err := d.QueryRow(
		"SELECT id, name, display_name, created_at, active FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Name, &u.DisplayName, &createdAt, &active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	u.CreatedAt = time.Unix(createdAt, 0)
	u.Active = active == 1
	return &u, nil
}

// GetUserByName retrieves a user by username
func (d *DB) GetUserByName(name string) (*User, error) {
	var u User
	var createdAt int64
	var active int

	err := d.QueryRow(
		"SELECT id, name, display_name, created_at, active FROM users WHERE name = ?",
		name,
	).Scan(&u.ID, &u.Name, &u.DisplayName, &createdAt, &active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	u.CreatedAt = time.Unix(createdAt, 0)
	u.Active = active == 1
	return &u, nil
}

// ListUsers returns all users
func (d *DB) ListUsers() ([]*User, error) {
	rows, err := d.Query(
		"SELECT id, name, display_name, created_at, active FROM users ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var u User
		var createdAt int64
		var active int

		if err := rows.Scan(&u.ID, &u.Name, &u.DisplayName, &createdAt, &active); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		u.CreatedAt = time.Unix(createdAt, 0)
		u.Active = active == 1
		users = append(users, &u)
	}

	return users, rows.Err()
}

// ListActiveUsers returns all active users
func (d *DB) ListActiveUsers() ([]*User, error) {
	rows, err := d.Query(
		"SELECT id, name, display_name, created_at, active FROM users WHERE active = 1 ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list active users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var u User
		var createdAt int64
		var active int

		if err := rows.Scan(&u.ID, &u.Name, &u.DisplayName, &createdAt, &active); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		u.CreatedAt = time.Unix(createdAt, 0)
		u.Active = active == 1
		users = append(users, &u)
	}

	return users, rows.Err()
}

// DeactivateUser sets a user's active status to false
func (d *DB) DeactivateUser(id []byte) error {
	result, err := d.Exec("UPDATE users SET active = 0 WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ActivateUser sets a user's active status to true
func (d *DB) ActivateUser(id []byte) error {
	result, err := d.Exec("UPDATE users SET active = 1 WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to activate user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// DeleteUser permanently deletes a user (cascades to credentials, sessions, ACLs)
func (d *DB) DeleteUser(id []byte) error {
	result, err := d.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// unixNow returns the current unix timestamp
func unixNow() int64 {
	return time.Now().Unix()
}

// PendingUser represents a user awaiting approval
type PendingUser struct {
	ID          []byte
	Fingerprint string
	CreatedAt   time.Time
}

// GetUserByFingerprint looks up a user by their SSH key fingerprint
func (d *DB) GetUserByFingerprint(fingerprint string) ([]byte, string, error) {
	var userID []byte
	var status string

	err := d.QueryRow(`
		SELECT u.id, u.status
		FROM users u
		JOIN ssh_keys sk ON sk.user_id = u.id
		WHERE sk.fingerprint = ?
	`, fingerprint).Scan(&userID, &status)

	if err != nil {
		return nil, "", err
	}
	return userID, status, nil
}

// CreateUserWithFingerprint creates a new user with an SSH key fingerprint.
// displayName is typically the SSH username (e.g. "daniel").
func (d *DB) CreateUserWithFingerprint(fingerprint, status, displayName string) ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("failed to generate user ID: %w", err)
	}

	now := unixNow()

	name := displayName
	if name == "" {
		name = fingerprint
	}

	_, err := d.Exec(
		"INSERT INTO users (id, name, display_name, created_at, active, status) VALUES (?, ?, ?, ?, 1, ?)",
		id, name, displayName, now, status,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Add the SSH key
	_, err = d.Exec(
		"INSERT INTO ssh_keys (fingerprint, user_id, created_at) VALUES (?, ?, ?)",
		fingerprint, id, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add ssh key: %w", err)
	}

	return id, nil
}

// IsFirstUser returns true if there are no users in the database
func (d *DB) IsFirstUser() (bool, error) {
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

// ListPendingUsers returns all users with pending status
func (d *DB) ListPendingUsers() ([]PendingUser, error) {
	rows, err := d.Query(`
		SELECT u.id, sk.fingerprint, u.created_at
		FROM users u
		JOIN ssh_keys sk ON sk.user_id = u.id
		WHERE u.status = 'pending'
		ORDER BY u.created_at
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending users: %w", err)
	}
	defer rows.Close()

	var users []PendingUser
	for rows.Next() {
		var u PendingUser
		var createdAt int64
		if err := rows.Scan(&u.ID, &u.Fingerprint, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan pending user: %w", err)
		}
		u.CreatedAt = time.Unix(createdAt, 0)
		users = append(users, u)
	}

	return users, rows.Err()
}

// ApproveUser changes a user's status from pending to approved
func (d *DB) ApproveUser(id []byte) error {
	result, err := d.Exec("UPDATE users SET status = 'approved' WHERE id = ? AND status = 'pending'", id)
	if err != nil {
		return fmt.Errorf("failed to approve user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("user not found or already approved")
	}

	return nil
}

// AddSSHKey adds an SSH key to an existing user
func (d *DB) AddSSHKey(userID []byte, fingerprint, comment string) error {
	now := unixNow()
	_, err := d.Exec(
		"INSERT INTO ssh_keys (fingerprint, user_id, comment, created_at) VALUES (?, ?, ?, ?)",
		fingerprint, userID, comment, now,
	)
	if err != nil {
		return fmt.Errorf("failed to add ssh key: %w", err)
	}
	return nil
}

// ListSSHKeys returns all SSH keys for a user
func (d *DB) ListSSHKeys(userID []byte) ([]string, error) {
	rows, err := d.Query("SELECT fingerprint FROM ssh_keys WHERE user_id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list ssh keys: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("failed to scan ssh key: %w", err)
		}
		keys = append(keys, fp)
	}

	return keys, rows.Err()
}
