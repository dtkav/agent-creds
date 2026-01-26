package db

import (
	"database/sql"
	"fmt"
	"time"
)

// Credential represents a FIDO2/WebAuthn credential
type Credential struct {
	ID        []byte // Credential ID from WebAuthn
	UserID    []byte
	PublicKey []byte // COSE public key
	SignCount uint32
	AAGUID    []byte // Authenticator AAGUID
	CreatedAt time.Time
	LastUsed  *time.Time
}

// CreateCredential stores a new FIDO2 credential
func (d *DB) CreateCredential(cred *Credential) error {
	now := unixNow()

	_, err := d.Exec(
		`INSERT INTO credentials (id, user_id, public_key, sign_count, aaguid, created_at, last_used)
		 VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		cred.ID, cred.UserID, cred.PublicKey, cred.SignCount, cred.AAGUID, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	cred.CreatedAt = time.Unix(now, 0)
	return nil
}

// GetCredential retrieves a credential by ID
func (d *DB) GetCredential(id []byte) (*Credential, error) {
	var c Credential
	var createdAt int64
	var lastUsed sql.NullInt64

	err := d.QueryRow(
		`SELECT id, user_id, public_key, sign_count, aaguid, created_at, last_used
		 FROM credentials WHERE id = ?`,
		id,
	).Scan(&c.ID, &c.UserID, &c.PublicKey, &c.SignCount, &c.AAGUID, &createdAt, &lastUsed)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	c.CreatedAt = time.Unix(createdAt, 0)
	if lastUsed.Valid {
		t := time.Unix(lastUsed.Int64, 0)
		c.LastUsed = &t
	}

	return &c, nil
}

// GetCredentialsByUser retrieves all credentials for a user
func (d *DB) GetCredentialsByUser(userID []byte) ([]*Credential, error) {
	rows, err := d.Query(
		`SELECT id, user_id, public_key, sign_count, aaguid, created_at, last_used
		 FROM credentials WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	defer rows.Close()

	var creds []*Credential
	for rows.Next() {
		var c Credential
		var createdAt int64
		var lastUsed sql.NullInt64

		if err := rows.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.SignCount, &c.AAGUID, &createdAt, &lastUsed); err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		c.CreatedAt = time.Unix(createdAt, 0)
		if lastUsed.Valid {
			t := time.Unix(lastUsed.Int64, 0)
			c.LastUsed = &t
		}

		creds = append(creds, &c)
	}

	return creds, rows.Err()
}

// UpdateCredentialSignCount updates the sign count and last used time
func (d *DB) UpdateCredentialSignCount(id []byte, signCount uint32) error {
	now := unixNow()

	result, err := d.Exec(
		"UPDATE credentials SET sign_count = ?, last_used = ? WHERE id = ?",
		signCount, now, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update sign count: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("credential not found")
	}

	return nil
}

// DeleteCredential removes a credential
func (d *DB) DeleteCredential(id []byte) error {
	result, err := d.Exec("DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("credential not found")
	}

	return nil
}

// CountCredentialsByUser returns the number of credentials for a user
func (d *DB) CountCredentialsByUser(userID []byte) (int, error) {
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM credentials WHERE user_id = ?", userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count credentials: %w", err)
	}
	return count, nil
}
