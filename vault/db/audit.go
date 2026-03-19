package db

import (
	"fmt"
	"strings"
	"time"
)

// AuditEntry represents a row in the audit_log table.
type AuditEntry struct {
	ID          int64
	Timestamp   time.Time
	Decision    string
	Method      string
	Host        string
	Path        string
	Reason      *string
	TokenID     *string
	Fingerprint *string
}

// InsertAuditEntry writes an audit entry to the audit_log table.
func (d *DB) InsertAuditEntry(entry *AuditEntry) error {
	_, err := d.Exec(
		`INSERT INTO audit_log (timestamp, decision, method, host, path, reason, token_id, fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp.Unix(),
		entry.Decision,
		entry.Method,
		entry.Host,
		entry.Path,
		entry.Reason,
		entry.TokenID,
		entry.Fingerprint,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}
	return nil
}

// AuditFilter specifies optional filters for QueryAuditLog.
type AuditFilter struct {
	Decision *string
	Host     *string
	Since    *time.Time
	Limit    int
}

// QueryAuditLog retrieves audit entries matching the given filter.
func (d *DB) QueryAuditLog(filter AuditFilter) ([]AuditEntry, error) {
	query := `SELECT id, timestamp, decision, method, host, path, reason, token_id, fingerprint FROM audit_log`
	var conditions []string
	var args []interface{}

	if filter.Decision != nil {
		conditions = append(conditions, "decision = ?")
		args = append(args, *filter.Decision)
	}
	if filter.Host != nil {
		conditions = append(conditions, "host = ?")
		args = append(args, *filter.Host)
	}
	if filter.Since != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.Since.Unix())
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit log: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Decision, &e.Method, &e.Host, &e.Path, &e.Reason, &e.TokenID, &e.Fingerprint); err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}
		e.Timestamp = time.Unix(ts, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// DeleteOldAuditEntries removes audit log entries older than the given duration.
func (d *DB) DeleteOldAuditEntries(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).Unix()
	result, err := d.Exec("DELETE FROM audit_log WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit entries: %w", err)
	}
	return result.RowsAffected()
}
