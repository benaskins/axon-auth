package auth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth "github.com/benaskins/axon-auth"
)

func TestRegistrationBegin(t *testing.T) {
	server, users, _, _, invites := setupTestServer(t)

	// Create invite
	token, hash, _ := auth.GenerateToken()
	invites.CreateInvite("test@example.com", hash, time.Now().Add(24*time.Hour), false)

	body := map[string]string{
		"token":        token,
		"username":     "testuser",
		"display_name": "Test User",
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/register/begin", bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["user_id"] == nil {
		t.Error("expected user_id in response")
	}
	if response["options"] == nil {
		t.Error("expected options in response")
	}

	// Verify user was created
	user, err := users.GetUserByEmail("test@example.com")
	if err != nil {
		t.Errorf("user should be created: %v", err)
	}
	if user.DisplayName != "Test User" {
		t.Errorf("expected display name Test User, got %s", user.DisplayName)
	}
}

func TestRegistrationBegin_UsernameValidation(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantCode int
	}{
		{"too short", "a", http.StatusBadRequest},
		{"invalid chars", "Test_User!", http.StatusBadRequest},
		{"starts with hyphen", "-user", http.StatusBadRequest},
		{"ends with hyphen", "user-", http.StatusBadRequest},
		{"valid simple", "ben", http.StatusOK},
		{"valid with hyphens", "ben-askins", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _, _, inv := setupTestServer(t)
			tok, hash, _ := auth.GenerateToken()
			inv.CreateInvite("test-"+tt.username+"@example.com", hash, time.Now().Add(24*time.Hour), false)

			body := map[string]string{
				"token":        tok,
				"username":     tt.username,
				"display_name": "Test",
			}
			bodyJSON, _ := json.Marshal(body)
			req, _ := http.NewRequest("POST", "/api/register/begin", bytes.NewBuffer(bodyJSON))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("username %q: expected %d, got %d: %s", tt.username, tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestRegistrationBegin_UsernameUniqueness(t *testing.T) {
	server, users, _, _, invites := setupTestServer(t)

	// Create an existing user with username "taken"
	users.CreateUser("taken", "existing@example.com", "Existing User", false)

	token, hash, _ := auth.GenerateToken()
	invites.CreateInvite("new@example.com", hash, time.Now().Add(24*time.Hour), false)

	body := map[string]string{
		"token":        token,
		"username":     "taken",
		"display_name": "New User",
	}
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "/api/register/begin", bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegistrationBegin_InvalidToken(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	body := map[string]string{
		"token":        "invalid",
		"username":     "testuser",
		"display_name": "Test User",
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/register/begin", bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}
