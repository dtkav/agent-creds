package db

import (
	"database/sql"
	"fmt"
	"time"
)

// Token represents a stored token (.akey content)
type Token struct {
	ID          string // Token name (e.g., "stripe-prod")
	Macaroon    string // The sk_xxx token
	Description string
	CreatedAt   time.Time
	CreatedBy   []byte // User ID who created it
}

// TokenACL represents access grant for a user to a token
type TokenACL struct {
	TokenID   string
	UserID    []byte
	GrantedAt time.Time
	GrantedBy []byte
}

// CreateToken stores a new token
func (d *DB) CreateToken(token *Token) error {
	now := unixNow()

	_, err := d.Exec(
		`INSERT INTO tokens (id, macaroon, description, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?)`,
		token.ID, token.Macaroon, token.Description, now, token.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	token.CreatedAt = time.Unix(now, 0)
	return nil
}

// GetToken retrieves a token by ID
func (d *DB) GetToken(id string) (*Token, error) {
	var t Token
	var createdAt int64

	err := d.QueryRow(
		`SELECT id, macaroon, description, created_at, created_by
		 FROM tokens WHERE id = ?`,
		id,
	).Scan(&t.ID, &t.Macaroon, &t.Description, &createdAt, &t.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	t.CreatedAt = time.Unix(createdAt, 0)
	return &t, nil
}

// ListTokens returns all tokens
func (d *DB) ListTokens() ([]*Token, error) {
	rows, err := d.Query(
		`SELECT id, macaroon, description, created_at, created_by
		 FROM tokens ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		var t Token
		var createdAt int64

		if err := rows.Scan(&t.ID, &t.Macaroon, &t.Description, &createdAt, &t.CreatedBy); err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}

		t.CreatedAt = time.Unix(createdAt, 0)
		tokens = append(tokens, &t)
	}

	return tokens, rows.Err()
}

// ListTokensForUser returns all tokens a user has access to
func (d *DB) ListTokensForUser(userID []byte) ([]*Token, error) {
	rows, err := d.Query(
		`SELECT t.id, t.macaroon, t.description, t.created_at, t.created_by
		 FROM tokens t
		 JOIN token_acls a ON t.id = a.token_id
		 WHERE a.user_id = ?
		 ORDER BY t.id`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens for user: %w", err)
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		var t Token
		var createdAt int64

		if err := rows.Scan(&t.ID, &t.Macaroon, &t.Description, &createdAt, &t.CreatedBy); err != nil {
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}

		t.CreatedAt = time.Unix(createdAt, 0)
		tokens = append(tokens, &t)
	}

	return tokens, rows.Err()
}

// UpdateToken updates a token's macaroon and description
func (d *DB) UpdateToken(id string, macaroon, description string) error {
	result, err := d.Exec(
		"UPDATE tokens SET macaroon = ?, description = ? WHERE id = ?",
		macaroon, description, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update token: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("token not found")
	}

	return nil
}

// DeleteToken removes a token and all its ACLs
func (d *DB) DeleteToken(id string) error {
	result, err := d.Exec("DELETE FROM tokens WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("token not found")
	}

	return nil
}

// GrantTokenAccess grants a user access to a token
func (d *DB) GrantTokenAccess(tokenID string, userID, grantedBy []byte) error {
	now := unixNow()

	_, err := d.Exec(
		`INSERT OR REPLACE INTO token_acls (token_id, user_id, granted_at, granted_by)
		 VALUES (?, ?, ?, ?)`,
		tokenID, userID, now, grantedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to grant token access: %w", err)
	}

	return nil
}

// RevokeTokenAccess removes a user's access to a token
func (d *DB) RevokeTokenAccess(tokenID string, userID []byte) error {
	result, err := d.Exec(
		"DELETE FROM token_acls WHERE token_id = ? AND user_id = ?",
		tokenID, userID,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke token access: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("ACL not found")
	}

	return nil
}

// HasTokenAccess checks if a user has access to a token
func (d *DB) HasTokenAccess(tokenID string, userID []byte) (bool, error) {
	var count int
	err := d.QueryRow(
		"SELECT COUNT(*) FROM token_acls WHERE token_id = ? AND user_id = ?",
		tokenID, userID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check token access: %w", err)
	}
	return count > 0, nil
}

// ListTokenACLs returns all ACLs for a token
func (d *DB) ListTokenACLs(tokenID string) ([]*TokenACL, error) {
	rows, err := d.Query(
		`SELECT token_id, user_id, granted_at, granted_by
		 FROM token_acls WHERE token_id = ?`,
		tokenID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list token ACLs: %w", err)
	}
	defer rows.Close()

	var acls []*TokenACL
	for rows.Next() {
		var a TokenACL
		var grantedAt int64

		if err := rows.Scan(&a.TokenID, &a.UserID, &grantedAt, &a.GrantedBy); err != nil {
			return nil, fmt.Errorf("failed to scan ACL: %w", err)
		}

		a.GrantedAt = time.Unix(grantedAt, 0)
		acls = append(acls, &a)
	}

	return acls, rows.Err()
}

// GetTokenWithAccessCheck retrieves a token if the user has access
func (d *DB) GetTokenWithAccessCheck(tokenID string, userID []byte) (*Token, error) {
	hasAccess, err := d.HasTokenAccess(tokenID, userID)
	if err != nil {
		return nil, err
	}
	if !hasAccess {
		return nil, fmt.Errorf("access denied")
	}

	return d.GetToken(tokenID)
}
