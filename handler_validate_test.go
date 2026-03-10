package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth "github.com/benaskins/axon-auth"
	"github.com/benaskins/axon-auth/authtest"
)

func setupTestServer(t *testing.T) (*auth.Server, *authtest.MemoryUserStore, *authtest.MemorySessionStore, *authtest.MemoryPasskeyStore, *authtest.MemoryInviteStore) {
	t.Helper()

	users := authtest.NewMemoryUserStore()
	sessions := authtest.NewMemorySessionStore()
	passkeys := authtest.NewMemoryPasskeyStore()
	invites := authtest.NewMemoryInviteStore()

	cfg := auth.Config{
		RPID:            "auth.example.com",
		RPDisplayName:   "Test Auth",
		RPOrigins:       []string{"https://auth.example.com"},
		CookieDomain:    ".example.com",
		SecureCookie:    true,
		BaseURL:         "https://auth.example.com",
		SessionDuration: 7 * 24 * time.Hour,
		InviteDuration:  24 * time.Hour,
		InternalAPIKey:  "test-internal-api-key",
	}

	server, err := auth.NewServer(cfg, users, sessions, passkeys, invites, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return server, users, sessions, passkeys, invites
}

func TestValidateEndpoint_Valid(t *testing.T) {
	server, users, sessions, _, _ := setupTestServer(t)

	user, _ := users.CreateUser("testuser", "test@example.com", "Test User", false)
	token, hash, _ := auth.GenerateToken()
	sessions.CreateSession(user.ID, hash, time.Now().Add(7*24*time.Hour))

	req, _ := http.NewRequest("GET", "/api/validate", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["user_id"] != user.ID {
		t.Errorf("expected user_id %s, got %v", user.ID, response["user_id"])
	}
	if response["username"] != user.Username {
		t.Errorf("expected username %s, got %v", user.Username, response["username"])
	}
	if response["email"] != user.Email {
		t.Errorf("expected email %s, got %v", user.Email, response["email"])
	}
}

func TestValidateEndpoint_NoCookie(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	req, _ := http.NewRequest("GET", "/api/validate", nil)
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestValidateEndpoint_UserNotFound(t *testing.T) {
	server, _, sessions, _, _ := setupTestServer(t)

	// Create session for a user ID that does not exist in the user store
	token, hash, _ := auth.GenerateToken()
	sessions.CreateSession("nonexistent-user", hash, time.Now().Add(7*24*time.Hour))

	req, _ := http.NewRequest("GET", "/api/validate", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["error"] != "user not found" {
		t.Errorf("expected 'user not found' error, got %v", response["error"])
	}
}

func TestValidateEndpoint_InvalidToken(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	req, _ := http.NewRequest("GET", "/api/validate", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "invalid-token"})
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}
