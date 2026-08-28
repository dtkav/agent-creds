package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"vault/db"
	tfmac "vault/macaroon"
)

// Server is the HTTP API server
type Server struct {
	db                *db.DB
	mux               *http.ServeMux
	webauthn          *WebAuthnHandler
	keyStore          *tfmac.KeyStore
	inventoryProvider InventoryProvider
}

// Option configures optional API capabilities.
type Option func(*Server)

// InventoryProvider returns a redacted view of the active Vault runtime.
type InventoryProvider func(context.Context) (InventoryResponse, error)

// WithInventoryProvider exposes non-secret runtime configuration metadata to
// authenticated dashboard clients.
func WithInventoryProvider(provider InventoryProvider) Option {
	return func(server *Server) {
		server.inventoryProvider = provider
	}
}

// NewServer creates a new API server
func NewServer(database *db.DB, keyStore *tfmac.KeyStore, rpID, rpOrigin, rpName, userVerification string, options ...Option) (*Server, error) {
	s := &Server{
		db:       database,
		mux:      http.NewServeMux(),
		keyStore: keyStore,
	}

	// Initialize WebAuthn handler
	wah, err := NewWebAuthnHandler(database, rpID, rpOrigin, rpName, userVerification)
	if err != nil {
		return nil, err
	}
	s.webauthn = wah
	for _, option := range options {
		option(s)
	}

	s.registerRoutes()
	return s, nil
}

// registerRoutes sets up all HTTP routes
func (s *Server) registerRoutes() {
	// User management
	s.mux.HandleFunc("/api/users", s.handleUsers)
	s.mux.HandleFunc("/api/users/", s.handleUserByID)

	// WebAuthn registration
	s.mux.HandleFunc("/api/webauthn/register/begin", s.handleRegisterBegin)
	s.mux.HandleFunc("/api/webauthn/register/finish", s.handleRegisterFinish)

	// CLI Authentication (FIDO2)
	s.mux.HandleFunc("/api/auth/challenge", s.handleAuthChallenge)
	s.mux.HandleFunc("/api/auth/verify", s.handleAuthVerify)

	// Browser passkey authentication (discoverable and username-assisted)
	s.mux.HandleFunc("/api/passkeys/authenticate/begin", s.handlePasskeyAuthenticationBegin)
	s.mux.HandleFunc("/api/passkeys/authenticate/finish", s.handlePasskeyAuthenticationFinish)

	// Token management
	s.mux.HandleFunc("/api/tokens", s.handleTokens)
	s.mux.HandleFunc("/api/tokens/", s.handleTokenByID)

	// Audit log
	s.mux.HandleFunc("/api/audit", s.handleAudit)
	s.mux.HandleFunc("/api/mints", s.handleMints)
	s.mux.HandleFunc("/api/inventory", s.handleInventory)

	// Recent denials (unauthenticated, for adev polling)
	s.mux.HandleFunc("/api/denials", s.handleDenials)

	// Enrollment page
	s.mux.HandleFunc("/enroll", s.handleEnrollPage)
	s.mux.HandleFunc("/assets/vault.css", s.handleDashboardCSS)
	s.mux.HandleFunc("/assets/vault.js", s.handleDashboardJS)
	s.mux.HandleFunc("/", s.handleDashboard)

	// Health check
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers for browser-based WebAuthn
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	s.mux.ServeHTTP(w, r)
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
	}
}

// writeError writes a JSON error response
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// readJSON reads a JSON request body
func readJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// getSessionUser extracts and validates the session from Authorization header
func (s *Server) getSessionUser(r *http.Request) ([]byte, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, nil
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	return s.db.ValidateSession(token)
}

// requireSession returns the user ID or writes an error response
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	userID, err := s.getSessionUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return nil, false
	}
	if userID == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return userID, true
}
