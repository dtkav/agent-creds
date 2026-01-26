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
