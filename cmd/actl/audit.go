package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/lipgloss"
	_ "github.com/mattn/go-sqlite3"
)

func runAuditLog(args []string) {
	var (
		recent  bool
		denials bool
		host    string
		limit   int
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--recent":
			recent = true
		case "--denials":
			denials = true
		case "--host":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --host requires a value")
				os.Exit(1)
			}
			host = args[i]
		case "--limit":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: --limit requires a value")
				os.Exit(1)
			}
			if _, err := fmt.Sscanf(args[i], "%d", &limit); err != nil {
				fmt.Fprintf(os.Stderr, "Error: --limit requires a number, got %q\n", args[i])
				os.Exit(1)
			}
		case "-h", "--help", "help":
			auditLogUsage()
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", args[i])
			auditLogUsage()
			os.Exit(1)
		}
	}

	dbPath := os.Getenv("AUTHZ_DB_PATH")
	if dbPath == "" {
		if _, err := os.Stat("/data"); err == nil {
			dbPath = "/data/authz.db"
		} else {
			home, _ := os.UserHomeDir()
			dbPath = filepath.Join(home, ".config", "agent-creds", "authz.db")
		}
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "No audit database found at %s\n", dbPath)
		os.Exit(1)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&mode=ro")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	query := `SELECT timestamp, decision, method, host, path, reason FROM audit_log`
	var conditions []string
	var queryArgs []interface{}

	if recent {
		conditions = append(conditions, "timestamp >= ?")
		queryArgs = append(queryArgs, time.Now().Add(-1*time.Hour).Unix())
	}
	if denials {
		conditions = append(conditions, "decision = ?")
		queryArgs = append(queryArgs, "deny")
	}
	if host != "" {
		conditions = append(conditions, "host = ?")
		queryArgs = append(queryArgs, host)
	}

	if len(conditions) > 0 {
		query += " WHERE "
		for i, c := range conditions {
			if i > 0 {
				query += " AND "
			}
			query += c
		}
	}
	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	} else if limit == 0 {
		query += " LIMIT 100"
	}

	rows, err := db.Query(query, queryArgs...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying audit log: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	allowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	denyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))

	count := 0
	for rows.Next() {
		var ts int64
		var decision, method, rowHost, path string
		var reason *string
		if err := rows.Scan(&ts, &decision, &method, &rowHost, &path, &reason); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading row: %v\n", err)
			os.Exit(1)
		}

		timestamp := time.Unix(ts, 0).Format("2006-01-02 15:04:05")

		var indicator string
		if decision == "allow" {
			indicator = allowStyle.Render("✓")
		} else {
			indicator = denyStyle.Render("✗")
		}

		reasonStr := ""
		if reason != nil && *reason != "" {
			reasonStr = *reason
		} else if decision == "allow" {
			reasonStr = "token:ok caveats:ok"
		}

		hostPath := rowHost
		if path != "" {
			hostPath += path
		}

		fmt.Printf("%s  %s  %-6s  %-40s  %s\n", timestamp, indicator, method, hostPath, reasonStr)
		count++
	}

	if count == 0 {
		fmt.Println("No audit log entries found.")
	}
}

func auditLogUsage() {
	fmt.Print(`Usage: actl vault log [options]

Display audit log entries from the vault database.

Options:
  --recent       Show entries from the last hour only
  --denials      Show only denied requests
  --host <host>  Filter by specific host
  --limit <N>    Maximum number of entries (default: 100)
`)
}
