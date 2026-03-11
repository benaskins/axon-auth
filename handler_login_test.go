package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auth "github.com/benaskins/axon-auth"
)

func TestLoginBegin(t *testing.T) {
	ctx := context.Background()
	server, users, _, _, _ := setupTestServer(t)

	// Create user (without passkeys)
	user, _ := users.CreateUser(ctx, "testuser", "test@example.com", "Test User", false)

	body := map[string]string{
		"email": user.Email,
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/login/begin", bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	// User has no passkeys registered, should return 401 with generic error
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["error"] != "invalid credentials" {
		t.Errorf("expected 'invalid credentials' error, got %v", response["error"])
	}
}

func TestLoginBegin_MissingEmail(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	body := map[string]string{}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/login/begin", bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["error"] != "email is required" {
		t.Errorf("expected 'email is required' error, got %v", response["error"])
	}
}

func TestLoginBegin_InvalidBody(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	req, _ := http.NewRequest("POST", "/api/login/begin", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLoginBegin_UserNotFound(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	body := map[string]string{
		"email": "nonexistent@example.com",
	}
	bodyJSON, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", "/api/login/begin", bytes.NewBuffer(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}
}

func TestLogout_NoCookie(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	req, _ := http.NewRequest("POST", "/api/logout", nil)
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	if response["message"] != "no session" {
		t.Errorf("expected 'no session' message, got %v", response["message"])
	}
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	server, users, sessions, _, _ := setupTestServer(t)

	// Create user and session
	user, _ := users.CreateUser(ctx, "testuser", "test@example.com", "Test User", false)
	token, hash, _ := auth.GenerateToken()
	sessions.CreateSession(ctx, user.ID, hash, time.Now().Add(7*24*time.Hour))

	req, _ := http.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: token})
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify session is deleted
	_, err := sessions.ValidateSessionByHash(ctx, hash)
	if err == nil {
		t.Error("session should be deleted")
	}
}
