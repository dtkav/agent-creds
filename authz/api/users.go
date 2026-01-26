package api

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

// CreateUserRequest is the request to create a user
type CreateUserRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
	Active      bool   `json:"active"`
}

// handleUsers handles GET /api/users and POST /api/users
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listUsers(w, r)
	case http.MethodPost:
		s.createUser(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// listUsers returns all users
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]UserResponse, len(users))
	for i, u := range users {
		response[i] = UserResponse{
			ID:          hex.EncodeToString(u.ID),
			Name:        u.Name,
			DisplayName: u.DisplayName,
			CreatedAt:   u.CreatedAt.Unix(),
			Active:      u.Active,
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// createUser creates a new user
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Check if user already exists
	existing, err := s.db.GetUserByName(req.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing != nil {
		writeError(w, http.StatusConflict, "user already exists")
		return
	}

	user, err := s.db.CreateUser(req.Name, req.DisplayName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, UserResponse{
		ID:          hex.EncodeToString(user.ID),
		Name:        user.Name,
		DisplayName: user.DisplayName,
		CreatedAt:   user.CreatedAt.Unix(),
		Active:      user.Active,
	})
}

// handleUserByID handles requests to /api/users/{id}
func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "user ID required")
		return
	}

	// Parse ID (support both hex and base64)
	userID, err := parseID(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getUser(w, r, userID)
	case http.MethodDelete:
		s.deactivateUser(w, r, userID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// getUser returns a single user
func (s *Server) getUser(w http.ResponseWriter, r *http.Request, userID []byte) {
	user, err := s.db.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, UserResponse{
		ID:          hex.EncodeToString(user.ID),
		Name:        user.Name,
		DisplayName: user.DisplayName,
		CreatedAt:   user.CreatedAt.Unix(),
		Active:      user.Active,
	})
}

// deactivateUser deactivates a user
func (s *Server) deactivateUser(w http.ResponseWriter, r *http.Request, userID []byte) {
	if err := s.db.DeactivateUser(userID); err != nil {
		if err.Error() == "user not found" {
			writeError(w, http.StatusNotFound, "user not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// parseID parses an ID from either hex or base64url format
func parseID(s string) ([]byte, error) {
	// Try hex first (32 chars for 16 bytes)
	if len(s) == 32 {
		return hex.DecodeString(s)
	}
	// Try base64url
	return base64.RawURLEncoding.DecodeString(s)
}
