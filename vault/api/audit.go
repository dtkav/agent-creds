package api

import (
	"net/http"
	"strconv"
	"time"

	"vault/db"
)

type auditEntryResponse struct {
	ID          int64   `json:"id"`
	Timestamp   string  `json:"timestamp"`
	Decision    string  `json:"decision"`
	Method      string  `json:"method"`
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	Reason      *string `json:"reason,omitempty"`
	TokenID     *string `json:"token_id,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if _, ok := s.requireSession(w, r); !ok {
		return
	}

	q := r.URL.Query()
	filter := db.AuditFilter{
		Limit: 100,
	}

	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since parameter: expected ISO 8601 timestamp")
			return
		}
		filter.Since = &t
	}

	if v := q.Get("decision"); v != "" {
		if v != "allow" && v != "deny" {
			writeError(w, http.StatusBadRequest, "decision must be 'allow' or 'deny'")
			return
		}
		filter.Decision = &v
	}

	if v := q.Get("host"); v != "" {
		filter.Host = &v
	}

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		filter.Limit = n
	}

	entries, err := s.db.QueryAuditLog(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}

	resp := make([]auditEntryResponse, len(entries))
	for i, e := range entries {
		resp[i] = auditEntryResponse{
			ID:          e.ID,
			Timestamp:   e.Timestamp.UTC().Format(time.RFC3339),
			Decision:    e.Decision,
			Method:      e.Method,
			Host:        e.Host,
			Path:        e.Path,
			Reason:      e.Reason,
			TokenID:     e.TokenID,
			Fingerprint: e.Fingerprint,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleDenials returns recent denial entries without requiring session auth.
// Used by adev for denial monitoring polling.
func (s *Server) handleDenials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	since := time.Now().Add(-30 * time.Second)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since parameter")
			return
		}
		since = t
	}

	deny := "deny"
	filter := db.AuditFilter{
		Decision: &deny,
		Since:    &since,
		Limit:    50,
	}

	entries, err := s.db.QueryAuditLog(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}

	resp := make([]auditEntryResponse, len(entries))
	for i, e := range entries {
		resp[i] = auditEntryResponse{
			ID:        e.ID,
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
			Decision:  e.Decision,
			Method:    e.Method,
			Host:      e.Host,
			Path:      e.Path,
			Reason:    e.Reason,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
