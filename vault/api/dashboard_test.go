package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dop251/goja/parser"
)

func TestDashboardIsStaticAndHardened(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	(&Server{}).handleDashboard(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", response.Code)
	}
	if got := response.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") || strings.Contains(got, "unsafe-inline") {
		t.Fatalf("unexpected content security policy: %q", got)
	}
	body := response.Body.String()
	for _, expected := range []string{`data-view-target="credentials"`, `data-view-target="mints"`, `data-view-target="tokens"`, `data-view-target="audit"`, "/assets/vault.js"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("dashboard omitted %q", expected)
		}
	}
	if strings.Contains(body, `id="username"`) || strings.Contains(body, "Vault username") {
		t.Fatal("dashboard exposed a username login field")
	}
	if strings.Contains(strings.ToLower(dashboardHTML+dashboardCSS+dashboardJS), "card") {
		t.Fatal("dashboard reintroduced card-based UI")
	}
}

func TestDashboardJavascriptUsesUsernameLessPasskeyLogin(t *testing.T) {
	if strings.Contains(dashboardJS, "authenticate(username)") || strings.Contains(dashboardJS, "$('username')") {
		t.Fatal("dashboard JavaScript retained username-assisted login UI")
	}
	if !strings.Contains(dashboardJS, "body:'{}'") {
		t.Fatal("dashboard does not start a username-less passkey ceremony")
	}
	if !strings.Contains(dashboardJS, "querySelectorAll('[data-view-target]')") {
		t.Fatal("dashboard does not wire the section navigation")
	}
}

func TestDashboardCredentialInventoryUsesCompactExpandableRows(t *testing.T) {
	for _, expected := range []string{"credential-summary", "credential-detail", "data-credential-toggle", "expandedCredentials: new Set()"} {
		if !strings.Contains(dashboardHTML+dashboardCSS+dashboardJS, expected) {
			t.Fatalf("dashboard omitted compact credential behavior %q", expected)
		}
	}
	if strings.Contains(dashboardJS, "scope.slice(0,8)") {
		t.Fatal("dashboard renders authorization scope into inventory rows")
	}
}

func TestDashboardRejectsUnknownPaths(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/secret", nil)
	response := httptest.NewRecorder()
	(&Server{}).handleDashboard(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", response.Code)
	}
}

func TestDashboardJavascriptNeverFetchesHotTokenRoute(t *testing.T) {
	if _, err := parser.ParseFile(nil, "vault.js", dashboardJS, 0); err != nil {
		t.Fatalf("dashboard JavaScript does not parse: %v", err)
	}
	if strings.Contains(dashboardJS, "/api/tokens/") {
		t.Fatal("dashboard JavaScript can request an individual hot token")
	}
	for _, endpoint := range []string{"/api/passkeys/authenticate/begin", "/api/passkeys/authenticate/finish", "/api/inventory", "/api/mints", "/api/audit", "/api/tokens"} {
		if !strings.Contains(dashboardJS, endpoint) {
			t.Fatalf("dashboard JavaScript omitted %s", endpoint)
		}
	}
}
