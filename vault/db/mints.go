package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// MintEntry is non-secret metadata about a capability issuance. The encoded
// capability is never accepted by this type and is never stored in mint_log.
type MintEntry struct {
	ID          int64
	Timestamp   time.Time
	Source      string
	UserID      []byte
	Username    *string
	Fingerprint *string
	Name        *string
	Credential  *string
	Hosts       []string
	Methods     []string
	Paths       []string
	ExpiresAt   *time.Time
	TokenID     *string
	Attestation bool
}

// InsertMintEntry records issuance metadata without recording the capability.
func (d *DB) InsertMintEntry(entry *MintEntry) error {
	if entry == nil {
		return fmt.Errorf("mint entry is required")
	}
	hosts, err := json.Marshal(entry.Hosts)
	if err != nil {
		return fmt.Errorf("encoding mint hosts: %w", err)
	}
	methods, err := json.Marshal(entry.Methods)
	if err != nil {
		return fmt.Errorf("encoding mint methods: %w", err)
	}
	paths, err := json.Marshal(entry.Paths)
	if err != nil {
		return fmt.Errorf("encoding mint paths: %w", err)
	}
	timestamp := entry.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	var expiresAt any
	if entry.ExpiresAt != nil {
		expiresAt = entry.ExpiresAt.Unix()
	}
	result, err := d.Exec(
		`INSERT INTO mint_log
		 (timestamp, source, user_id, fingerprint, name, credential, hosts, methods, paths, expires_at, token_id, attestation)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		timestamp.Unix(), entry.Source, entry.UserID, entry.Fingerprint, entry.Name,
		entry.Credential, string(hosts), string(methods), string(paths), expiresAt,
		entry.TokenID, entry.Attestation,
	)
	if err != nil {
		return fmt.Errorf("inserting mint entry: %w", err)
	}
	entry.ID, _ = result.LastInsertId()
	entry.Timestamp = timestamp
	return nil
}

// QueryMintLog returns recent mint metadata newest-first.
func (d *DB) QueryMintLog(since *time.Time, limit int) ([]MintEntry, error) {
	query := `SELECT m.id, m.timestamp, m.source, m.user_id,
		COALESCE(NULLIF(u.display_name, ''), u.name), m.fingerprint, m.name,
		m.credential, m.hosts, m.methods, m.paths, m.expires_at, m.token_id,
		m.attestation
		FROM mint_log m LEFT JOIN users u ON u.id = m.user_id`
	var args []any
	if since != nil {
		query += " WHERE m.timestamp >= ?"
		args = append(args, since.Unix())
	}
	query += " ORDER BY m.timestamp DESC, m.id DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying mint log: %w", err)
	}
	defer rows.Close()

	var entries []MintEntry
	for rows.Next() {
		var entry MintEntry
		var timestamp int64
		var username, fingerprint, name, credential, tokenID sql.NullString
		var hosts, methods, paths string
		var expiresAt sql.NullInt64
		var attestation bool
		if err := rows.Scan(
			&entry.ID, &timestamp, &entry.Source, &entry.UserID, &username,
			&fingerprint, &name, &credential, &hosts, &methods, &paths,
			&expiresAt, &tokenID, &attestation,
		); err != nil {
			return nil, fmt.Errorf("scanning mint entry: %w", err)
		}
		entry.Timestamp = time.Unix(timestamp, 0)
		entry.Username = nullableString(username)
		entry.Fingerprint = nullableString(fingerprint)
		entry.Name = nullableString(name)
		entry.Credential = nullableString(credential)
		entry.TokenID = nullableString(tokenID)
		entry.Attestation = attestation
		if expiresAt.Valid {
			value := time.Unix(expiresAt.Int64, 0)
			entry.ExpiresAt = &value
		}
		if err := json.Unmarshal([]byte(hosts), &entry.Hosts); err != nil {
			return nil, fmt.Errorf("decoding mint hosts: %w", err)
		}
		if err := json.Unmarshal([]byte(methods), &entry.Methods); err != nil {
			return nil, fmt.Errorf("decoding mint methods: %w", err)
		}
		if err := json.Unmarshal([]byte(paths), &entry.Paths); err != nil {
			return nil, fmt.Errorf("decoding mint paths: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func nullableString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}
