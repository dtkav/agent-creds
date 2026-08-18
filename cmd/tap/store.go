package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Operation struct {
	ID               int64   `json:"id"`
	Source           string  `json:"source"`
	AgentID          string  `json:"agent_id"`
	AgentName        string  `json:"agent_name"`
	Provider         string  `json:"provider"`
	Operation        string  `json:"operation"`
	Model            string  `json:"model"`
	StartedAt        string  `json:"started_at"`
	EndedAt          string  `json:"ended_at"`
	DurationMS       int64   `json:"duration_ms"`
	StatusCode       int     `json:"status_code"`
	Outcome          string  `json:"outcome"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	ReasoningTokens  int64   `json:"reasoning_tokens"`
	CostCredits      float64 `json:"cost_credits"`
	RequestBytes     int64   `json:"request_bytes"`
	ResponseBytes    int64   `json:"response_bytes"`
}

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	// This is deliberately an allowlist. There is no generic JSON, header,
	// URL, request-body, response-body, or metadata column.
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS operations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	source TEXT NOT NULL,
	provider TEXT NOT NULL,
	operation_name TEXT NOT NULL,
	model TEXT NOT NULL,
	started_at TEXT NOT NULL,
	ended_at TEXT NOT NULL,
	duration_ms INTEGER NOT NULL,
	status_code INTEGER NOT NULL,
	outcome TEXT NOT NULL,
	input_tokens INTEGER NOT NULL,
	output_tokens INTEGER NOT NULL,
	cache_read_tokens INTEGER NOT NULL,
	cache_write_tokens INTEGER NOT NULL,
	reasoning_tokens INTEGER NOT NULL,
	request_bytes INTEGER NOT NULL,
	response_bytes INTEGER NOT NULL,
	agent_name TEXT NOT NULL DEFAULT '',
	cost_credits REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS operations_ended_at ON operations(ended_at DESC);
CREATE INDEX IF NOT EXISTS operations_source ON operations(source, ended_at DESC);
`)
	if err != nil {
		return err
	}
	rows, err := s.db.Query(`PRAGMA table_info(operations)`)
	if err != nil {
		return err
	}
	hasAgentName := false
	hasCostCredits := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(
			&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey,
		); err != nil {
			rows.Close()
			return err
		}
		hasAgentName = hasAgentName || name == "agent_name"
		hasCostCredits = hasCostCredits || name == "cost_credits"
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if !hasAgentName {
		if _, err = s.db.Exec(`ALTER TABLE operations ADD COLUMN agent_name TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !hasCostCredits {
		_, err = s.db.Exec(`ALTER TABLE operations ADD COLUMN cost_credits REAL NOT NULL DEFAULT 0`)
	}
	return err
}

func (s *Store) Insert(op *Operation) error {
	if op.AgentID == "" {
		op.AgentID = op.Source
	}
	result, err := s.db.Exec(`
INSERT INTO operations (
	source, provider, operation_name, model, started_at, ended_at,
	duration_ms, status_code, outcome, input_tokens, output_tokens,
	cache_read_tokens, cache_write_tokens, reasoning_tokens,
	request_bytes, response_bytes, agent_name, cost_credits
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.Source, op.Provider, op.Operation, op.Model, op.StartedAt, op.EndedAt,
		op.DurationMS, op.StatusCode, op.Outcome, op.InputTokens, op.OutputTokens,
		op.CacheReadTokens, op.CacheWriteTokens, op.ReasoningTokens,
		op.RequestBytes, op.ResponseBytes, op.AgentName, op.CostCredits)
	if err != nil {
		return err
	}
	op.ID, err = result.LastInsertId()
	return err
}

func (s *Store) Recent(limit int) ([]Operation, error) {
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	return s.queryOperations(`
SELECT id, source, provider, operation_name, model, started_at, ended_at,
	duration_ms, status_code, outcome, input_tokens, output_tokens,
	cache_read_tokens, cache_write_tokens, reasoning_tokens,
	request_bytes, response_bytes, agent_name, cost_credits
FROM operations
WHERE NOT (input_tokens = 0 AND output_tokens = 0 AND duration_ms >= 300000)
ORDER BY id DESC LIMIT ?`, limit)
}

func (s *Store) Since(since time.Time, limit int) ([]Operation, error) {
	if limit < 1 || limit > 20000 {
		limit = 20000
	}
	return s.queryOperations(`
SELECT id, source, provider, operation_name, model, started_at, ended_at,
	duration_ms, status_code, outcome, input_tokens, output_tokens,
	cache_read_tokens, cache_write_tokens, reasoning_tokens,
	request_bytes, response_bytes, agent_name, cost_credits
FROM operations
WHERE ended_at >= ?
	AND NOT (input_tokens = 0 AND output_tokens = 0 AND duration_ms >= 300000)
ORDER BY id DESC LIMIT ?`, since.UTC().Format(time.RFC3339Nano), limit)
}

func (s *Store) queryOperations(query string, arguments ...any) ([]Operation, error) {
	rows, err := s.db.Query(query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var operations []Operation
	for rows.Next() {
		var op Operation
		if err := rows.Scan(
			&op.ID, &op.Source, &op.Provider, &op.Operation, &op.Model,
			&op.StartedAt, &op.EndedAt, &op.DurationMS, &op.StatusCode,
			&op.Outcome, &op.InputTokens, &op.OutputTokens,
			&op.CacheReadTokens, &op.CacheWriteTokens, &op.ReasoningTokens,
			&op.RequestBytes, &op.ResponseBytes, &op.AgentName, &op.CostCredits,
		); err != nil {
			return nil, err
		}
		op.AgentID = op.Source
		operations = append(operations, op)
	}
	return operations, rows.Err()
}

type MetricRow struct {
	AgentID          string
	AgentName        string
	Provider         string
	Model            string
	Outcome          string
	Operations       int64
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	ReasoningTokens  int64
	CostCredits      float64
	DurationMS       int64
}

func (s *Store) Metrics() ([]MetricRow, error) {
	rows, err := s.db.Query(`
SELECT source, agent_name, provider, model, outcome, COUNT(*),
	SUM(input_tokens), SUM(output_tokens), SUM(cache_read_tokens),
	SUM(cache_write_tokens), SUM(reasoning_tokens), SUM(cost_credits), SUM(duration_ms)
FROM operations
WHERE NOT (input_tokens = 0 AND output_tokens = 0 AND duration_ms >= 300000)
GROUP BY source, agent_name, provider, model, outcome`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var metrics []MetricRow
	for rows.Next() {
		var row MetricRow
		if err := rows.Scan(
			&row.AgentID, &row.AgentName,
			&row.Provider, &row.Model, &row.Outcome, &row.Operations,
			&row.InputTokens, &row.OutputTokens, &row.CacheReadTokens,
			&row.CacheWriteTokens, &row.ReasoningTokens, &row.CostCredits,
			&row.DurationMS,
		); err != nil {
			return nil, err
		}
		metrics = append(metrics, row)
	}
	return metrics, rows.Err()
}

func operationTimes(start, end time.Time) (string, string, int64) {
	if end.Before(start) {
		end = start
	}
	return start.UTC().Format(time.RFC3339Nano), end.Format(time.RFC3339Nano),
		end.Sub(start).Milliseconds()
}

func (op Operation) validate() error {
	if op.Source == "" || op.Provider == "" || op.Operation == "" {
		return fmt.Errorf("operation identity is incomplete")
	}
	return nil
}
