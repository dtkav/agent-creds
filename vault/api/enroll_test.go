package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"vault/db"
)

func TestEnrollmentInfersSoleActiveUser(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/authz.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.CreateUser("agent", "agent"); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	response := httptest.NewRecorder()
	(&Server{db: database}).handleEnrollPage(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("enrollment status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/enroll?user=agent" {
		t.Fatalf("enrollment redirect = %q", location)
	}
}

func TestEnrollmentRequiresExplicitUserWhenAmbiguous(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/authz.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, username := range []string{"agent-a", "agent-b"} {
		if _, err := database.CreateUser(username, username); err != nil {
			t.Fatal(err)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	response := httptest.NewRecorder()
	(&Server{db: database}).handleEnrollPage(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous enrollment status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}
