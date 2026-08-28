package api

import (
	"net/http"
	"strconv"
	"time"

	"vault/db"
)

type mintEntryResponse struct {
	ID          int64    `json:"id"`
	Timestamp   string   `json:"timestamp"`
	Source      string   `json:"source"`
	Username    *string  `json:"username,omitempty"`
	Fingerprint *string  `json:"fingerprint,omitempty"`
	Name        *string  `json:"name,omitempty"`
	Credential  *string  `json:"credential,omitempty"`
	Hosts       []string `json:"hosts"`
	Methods     []string `json:"methods"`
	Paths       []string `json:"paths"`
	ExpiresAt   *string  `json:"expiresAt,omitempty"`
	TokenID     *string  `json:"tokenId,omitempty"`
	Attestation bool     `json:"attestation"`
}

func (s *Server) handleMints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	var since *time.Time
	if value := r.URL.Query().Get("since"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since parameter: expected ISO 8601 timestamp")
			return
		}
		since = &parsed
	}
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 500 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	entries, err := s.db.QueryMintLog(since, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query mint log")
		return
	}
	response := make([]mintEntryResponse, len(entries))
	for i, entry := range entries {
		response[i] = mintResponse(entry)
	}
	writeJSON(w, http.StatusOK, response)
}

func mintResponse(entry db.MintEntry) mintEntryResponse {
	response := mintEntryResponse{
		ID:          entry.ID,
		Timestamp:   entry.Timestamp.UTC().Format(time.RFC3339),
		Source:      entry.Source,
		Username:    entry.Username,
		Fingerprint: entry.Fingerprint,
		Name:        entry.Name,
		Credential:  entry.Credential,
		Hosts:       entry.Hosts,
		Methods:     entry.Methods,
		Paths:       entry.Paths,
		TokenID:     entry.TokenID,
		Attestation: entry.Attestation,
	}
	if entry.ExpiresAt != nil {
		formatted := entry.ExpiresAt.UTC().Format(time.RFC3339)
		response.ExpiresAt = &formatted
	}
	return response
}
