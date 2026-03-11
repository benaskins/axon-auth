package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServiceUserHandler_CreatesUserAndSession(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"username":     "xagent-runner",
		"display_name": "Test Runner",
	})
	req := httptest.NewRequest(http.MethodPost, "/internal/service-user", bytes.NewReader(body))
	req.Header.Set("X-Internal-API-Key", "test-internal-api-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["user_id"] == "" {
		t.Error("expected user_id in response")
	}
	if resp["session_token"] == "" {
		t.Error("expected session_token in response")
	}
}

func TestServiceUserHandler_Idempotent(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	makeRequest := func() map[string]string {
		body, _ := json.Marshal(map[string]string{
			"username":     "xagent-runner",
			"display_name": "Test Runner",
		})
		req := httptest.NewRequest(http.MethodPost, "/internal/service-user", bytes.NewReader(body))
		req.Header.Set("X-Internal-API-Key", "test-internal-api-key")
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		return resp
	}

	resp1 := makeRequest()
	resp2 := makeRequest()

	if resp1["user_id"] != resp2["user_id"] {
		t.Errorf("expected same user_id, got %q and %q", resp1["user_id"], resp2["user_id"])
	}
	if resp1["session_token"] == resp2["session_token"] {
		t.Error("expected different session tokens on second call")
	}
}

func TestServiceUserHandler_InvalidBody(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/internal/service-user", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-Internal-API-Key", "test-internal-api-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestServiceUserHandler_DefaultDisplayName(t *testing.T) {
	ctx := context.Background()
	server, users, _, _, _ := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"username": "xagent-nodisplay",
	})
	req := httptest.NewRequest(http.MethodPost, "/internal/service-user", bytes.NewReader(body))
	req.Header.Set("X-Internal-API-Key", "test-internal-api-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	user, err := users.GetUserByUsername(ctx, "xagent-nodisplay")
	if err != nil {
		t.Fatalf("user not found: %v", err)
	}

	if user.DisplayName != "xagent-nodisplay" {
		t.Errorf("expected display_name to default to username, got %q", user.DisplayName)
	}
}

func TestServiceUserHandler_MissingUsername(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{"display_name": "Test Runner"})
	req := httptest.NewRequest(http.MethodPost, "/internal/service-user", bytes.NewReader(body))
	req.Header.Set("X-Internal-API-Key", "test-internal-api-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestServiceUserHandler_NoAPIKey(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"username":     "xagent-runner",
		"display_name": "Test Runner",
	})
	req := httptest.NewRequest(http.MethodPost, "/internal/service-user", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServiceUserHandler_WrongAPIKey(t *testing.T) {
	server, _, _, _, _ := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"username":     "xagent-runner",
		"display_name": "Test Runner",
	})
	req := httptest.NewRequest(http.MethodPost, "/internal/service-user", bytes.NewReader(body))
	req.Header.Set("X-Internal-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}
