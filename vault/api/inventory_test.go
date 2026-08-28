package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vault/db"
)

func TestInventoryRequiresSessionAndReturnsProviderResult(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/authz.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	user, err := database.CreateUser("operator", "Vault Operator")
	if err != nil {
		t.Fatal(err)
	}
	session, err := database.CreateSession(user.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		db: database,
		inventoryProvider: func(context.Context) (InventoryResponse, error) {
			return InventoryResponse{Generation: 7, Credentials: []CredentialInventory{{
				Name: "/records/prod", Type: "bearer",
				SecretRefs: []CredentialSecretPointer{{Field: "token", Reference: "records#TOKEN"}},
			}}}, nil
		},
	}

	unauthenticated := httptest.NewRecorder()
	server.handleInventory(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/inventory", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", unauthenticated.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/inventory", nil)
	request.Header.Set("Authorization", "Bearer "+session.ID)
	response := httptest.NewRecorder()
	server.handleInventory(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("inventory status = %d, body = %s", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "records#TOKEN") || strings.Contains(body, "resolved-secret") {
		t.Fatalf("unexpected inventory response: %s", body)
	}
}
