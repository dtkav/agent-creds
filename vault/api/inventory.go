package api

import (
	"net/http"
)

// InventoryResponse is a deliberately redacted view of active Vault config.
// It contains source pointers and policy metadata, never resolved values.
type InventoryResponse struct {
	Generation  uint64                `json:"generation"`
	Credentials []CredentialInventory `json:"credentials"`
	Policies    []PolicyInventory     `json:"policies"`
}

type CredentialInventory struct {
	Name        string                    `json:"name"`
	Type        string                    `json:"type"`
	Policy      string                    `json:"policy,omitempty"`
	Environment []string                  `json:"environment,omitempty"`
	SecretRefs  []CredentialSecretPointer `json:"secretRefs,omitempty"`
	Hosts       []string                  `json:"hosts,omitempty"`
	Endpoints   []CredentialEndpoint      `json:"endpoints,omitempty"`
}

type CredentialSecretPointer struct {
	Field     string `json:"field"`
	Reference string `json:"reference"`
}

type CredentialEndpoint struct {
	Methods     []string `json:"methods,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	Description string   `json:"description,omitempty"`
}

type PolicyInventory struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	if s.inventoryProvider == nil {
		writeError(w, http.StatusServiceUnavailable, "runtime inventory is unavailable")
		return
	}
	inventory, err := s.inventoryProvider(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read runtime inventory")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}
