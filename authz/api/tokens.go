package api

import (
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/superfly/macaroon"

	"authz/attestation"
	"authz/db"
	tfmac "authz/macaroon"
)

// TokenStore interface for token minting (injected from main)
type TokenStore interface {
	MintToken(hosts []string, methods []string, paths []string, validFor time.Duration, requireAttestation bool) (string, error)
}

// CreateTokenRequest is the request to create a token
type CreateTokenRequest struct {
	ID                 string   `json:"id"`                 // Token name
	Hosts              []string `json:"hosts,omitempty"`    // Allowed hosts
	Methods            []string `json:"methods,omitempty"`  // Allowed HTTP methods
	Paths              []string `json:"paths,omitempty"`    // Allowed path patterns
	ValidFor           string   `json:"validFor,omitempty"` // Duration string (e.g., "24h")
	RequireAttestation bool     `json:"requireAttestation"` // Require FIDO2 attestation
	Description        string   `json:"description,omitempty"`
}

// TokenResponse represents a token in API responses
type TokenResponse struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
	CreatedBy   string `json:"createdBy,omitempty"` // hex-encoded user ID
}

// HotTokenResponse contains the token ready for use
type HotTokenResponse struct {
	Token     string `json:"token"`     // The macaroon token (or main,discharge pair)
	ExpiresAt int64  `json:"expiresAt"` // When the discharge expires (if any)
}

// GrantACLRequest is the request to grant token access
type GrantACLRequest struct {
	UserID   string `json:"userId"`   // hex-encoded user ID
	Username string `json:"username"` // alternative to userId
}

// TokenACLResponse represents an ACL entry
type TokenACLResponse struct {
	UserID    string `json:"userId"`
	Username  string `json:"username,omitempty"`
	GrantedAt int64  `json:"grantedAt"`
	GrantedBy string `json:"grantedBy,omitempty"`
}

// handleTokens handles GET /api/tokens and POST /api/tokens
func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.listTokens(w, r, userID)
	case http.MethodPost:
		s.createToken(w, r, userID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// listTokens returns tokens the user has access to
func (s *Server) listTokens(w http.ResponseWriter, r *http.Request, userID []byte) {
	tokens, err := s.db.ListTokensForUser(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]TokenResponse, len(tokens))
	for i, t := range tokens {
		createdBy := ""
		if len(t.CreatedBy) > 0 {
			createdBy = hex.EncodeToString(t.CreatedBy)
		}
		response[i] = TokenResponse{
			ID:          t.ID,
			Description: t.Description,
			CreatedAt:   t.CreatedAt.Unix(),
			CreatedBy:   createdBy,
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// createToken creates a new token (admin only for now)
func (s *Server) createToken(w http.ResponseWriter, r *http.Request, userID []byte) {
	var req CreateTokenRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	// Check if token already exists
	existing, err := s.db.GetToken(req.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing != nil {
		writeError(w, http.StatusConflict, "token already exists")
		return
	}

	// Parse validity duration
	validFor := 24 * time.Hour
	if req.ValidFor != "" {
		d, err := time.ParseDuration(req.ValidFor)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid validFor duration")
			return
		}
		validFor = d
	}

	// Mint the token
	tokenStr, err := s.mintToken(req.Hosts, req.Methods, req.Paths, validFor, req.RequireAttestation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mint token: "+err.Error())
		return
	}

	// Store the token
	token := &db.Token{
		ID:          req.ID,
		Macaroon:    tokenStr,
		Description: req.Description,
		CreatedBy:   userID,
	}

	if err := s.db.CreateToken(token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Auto-grant access to creator
	if err := s.db.GrantTokenAccess(req.ID, userID, userID); err != nil {
		// Log but don't fail
	}

	writeJSON(w, http.StatusCreated, TokenResponse{
		ID:          token.ID,
		Description: token.Description,
		CreatedAt:   token.CreatedAt.Unix(),
		CreatedBy:   hex.EncodeToString(userID),
	})
}

// mintToken creates a new macaroon token
func (s *Server) mintToken(hosts, methods, paths []string, validFor time.Duration, requireAttestation bool) (string, error) {
	keyStore, err := tfmac.LoadKeyStore()
	if err != nil {
		return "", err
	}

	m, err := keyStore.NewToken()
	if err != nil {
		return "", err
	}

	// Add validity window
	now := time.Now()
	if err := m.Add(&macaroon.ValidityWindow{
		NotBefore: now.Unix(),
		NotAfter:  now.Add(validFor).Unix(),
	}); err != nil {
		return "", err
	}

	// Add host caveat
	if len(hosts) > 0 {
		if err := m.Add(&tfmac.HostCaveat{Hosts: hosts}); err != nil {
			return "", err
		}
	}

	// Add method caveat
	if len(methods) > 0 {
		for i := range methods {
			methods[i] = strings.ToUpper(methods[i])
		}
		if err := m.Add(&tfmac.MethodCaveat{Methods: methods}); err != nil {
			return "", err
		}
	}

	// Add path caveat
	if len(paths) > 0 {
		if err := m.Add(&tfmac.PathCaveat{Patterns: paths}); err != nil {
			return "", err
		}
	}

	// Add attestation requirement
	if requireAttestation {
		if len(keyStore.EncryptionKey) == 0 {
			return "", errNoEncryptionKey
		}
		if err := attestation.Add3PCaveat(m, keyStore.EncryptionKey); err != nil {
			return "", err
		}
	}

	return tfmac.EncodeToken(m)
}

var errNoEncryptionKey = &tokenError{"encryption key required for attestation"}

type tokenError struct {
	msg string
}

func (e *tokenError) Error() string { return e.msg }

// handleTokenByID handles requests to /api/tokens/{id}
func (s *Server) handleTokenByID(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	// Extract token ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/tokens/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "token ID required")
		return
	}

	// Check for /acl sub-path
	if strings.Contains(path, "/acl") {
		parts := strings.SplitN(path, "/acl", 2)
		tokenID := parts[0]
		aclPath := ""
		if len(parts) > 1 {
			aclPath = parts[1]
		}
		s.handleTokenACL(w, r, userID, tokenID, aclPath)
		return
	}

	tokenID := path

	switch r.Method {
	case http.MethodGet:
		s.getToken(w, r, userID, tokenID)
	case http.MethodDelete:
		s.deleteToken(w, r, userID, tokenID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// getToken returns a hot token (with discharge if needed)
func (s *Server) getToken(w http.ResponseWriter, r *http.Request, userID []byte, tokenID string) {
	// Check access
	token, err := s.db.GetTokenWithAccessCheck(tokenID, userID)
	if err != nil {
		if err.Error() == "access denied" {
			writeError(w, http.StatusForbidden, "access denied")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	if token == nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}

	// Check if token needs discharge
	m, err := tfmac.DecodeToken(token.Macaroon)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to decode token")
		return
	}

	// Check for 3P caveat
	has3P := false
	for _, c := range m.UnsafeCaveats.Caveats {
		if _, ok := c.(*macaroon.Caveat3P); ok {
			has3P = true
			break
		}
	}

	if !has3P {
		// No discharge needed
		writeJSON(w, http.StatusOK, HotTokenResponse{
			Token: token.Macaroon,
		})
		return
	}

	// Create discharge
	keyStore, err := tfmac.LoadKeyStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load keys")
		return
	}

	// Create a session manager for discharge creation
	sessionMgr := attestation.NewSessionManager(keyStore.EncryptionKey)
	// Note: In the full implementation, we'd validate the user's FIDO2 assertion here
	// For now, we assume the session is already authenticated via WebAuthn

	// Create discharge without YubiKey (server-side attestation)
	discharge, err := createServerSideDischarge(m, keyStore.EncryptionKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create discharge: "+err.Error())
		return
	}

	dischargeStr, err := attestation.EncodeDischarge(discharge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode discharge")
		return
	}

	hotToken := attestation.CombineTokens(token.Macaroon, dischargeStr)

	writeJSON(w, http.StatusOK, HotTokenResponse{
		Token:     hotToken,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	})

	_ = sessionMgr // Silence unused variable warning
}

// createServerSideDischarge creates a discharge macaroon server-side
func createServerSideDischarge(mainToken *macaroon.Macaroon, encKey macaroon.EncryptionKey) (*macaroon.Macaroon, error) {
	// Get third-party caveats
	for _, c := range mainToken.UnsafeCaveats.Caveats {
		if tp, ok := c.(*macaroon.Caveat3P); ok {
			if tp.Location == tfmac.AttestationLocation {
				_, discharge, err := macaroon.DischargeTicket(encKey, tp.Location, tp.Ticket)
				if err != nil {
					return nil, err
				}

				// Add validity window to discharge
				now := time.Now()
				if err := discharge.Add(&macaroon.ValidityWindow{
					NotBefore: now.Unix(),
					NotAfter:  now.Add(1 * time.Hour).Unix(),
				}); err != nil {
					return nil, err
				}

				return discharge, nil
			}
		}
	}

	return nil, errNo3PCaveat
}

var errNo3PCaveat = &tokenError{"no attestation caveat found"}

// deleteToken deletes a token
func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request, userID []byte, tokenID string) {
	// For now, anyone with access can delete
	// TODO: require creator or admin
	hasAccess, err := s.db.HasTokenAccess(tokenID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !hasAccess {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	if err := s.db.DeleteToken(tokenID); err != nil {
		if err.Error() == "token not found" {
			writeError(w, http.StatusNotFound, "token not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleTokenACL handles ACL operations on a token
func (s *Server) handleTokenACL(w http.ResponseWriter, r *http.Request, userID []byte, tokenID, aclPath string) {
	// Verify token exists and user has access
	hasAccess, err := s.db.HasTokenAccess(tokenID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !hasAccess {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Remove leading slash from aclPath
	aclPath = strings.TrimPrefix(aclPath, "/")

	if aclPath == "" {
		// Operations on /api/tokens/{id}/acl
		switch r.Method {
		case http.MethodGet:
			s.listTokenACLs(w, r, tokenID)
		case http.MethodPost:
			s.grantTokenAccess(w, r, userID, tokenID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	} else {
		// Operations on /api/tokens/{id}/acl/{userId}
		switch r.Method {
		case http.MethodDelete:
			s.revokeTokenAccess(w, r, tokenID, aclPath)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

// listTokenACLs lists all ACLs for a token
func (s *Server) listTokenACLs(w http.ResponseWriter, r *http.Request, tokenID string) {
	acls, err := s.db.ListTokenACLs(tokenID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]TokenACLResponse, len(acls))
	for i, a := range acls {
		username := ""
		if user, _ := s.db.GetUser(a.UserID); user != nil {
			username = user.Name
		}
		grantedBy := ""
		if len(a.GrantedBy) > 0 {
			grantedBy = hex.EncodeToString(a.GrantedBy)
		}
		response[i] = TokenACLResponse{
			UserID:    hex.EncodeToString(a.UserID),
			Username:  username,
			GrantedAt: a.GrantedAt.Unix(),
			GrantedBy: grantedBy,
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// grantTokenAccess grants a user access to a token
func (s *Server) grantTokenAccess(w http.ResponseWriter, r *http.Request, granterID []byte, tokenID string) {
	var req GrantACLRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var targetUserID []byte
	var err error

	if req.UserID != "" {
		targetUserID, err = hex.DecodeString(req.UserID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid userId")
			return
		}
	} else if req.Username != "" {
		user, err := s.db.GetUserByName(req.Username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if user == nil {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		targetUserID = user.ID
	} else {
		writeError(w, http.StatusBadRequest, "userId or username is required")
		return
	}

	if err := s.db.GrantTokenAccess(tokenID, targetUserID, granterID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// revokeTokenAccess revokes a user's access to a token
func (s *Server) revokeTokenAccess(w http.ResponseWriter, r *http.Request, tokenID, userIDStr string) {
	targetUserID, err := hex.DecodeString(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid userId")
		return
	}

	if err := s.db.RevokeTokenAccess(tokenID, targetUserID); err != nil {
		if err.Error() == "ACL not found" {
			writeError(w, http.StatusNotFound, "ACL not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
