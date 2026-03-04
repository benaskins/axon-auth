package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/benaskins/axon"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type loginBeginRequest struct {
	Email string `json:"email"`
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req loginBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Email == "" {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	// Get user
	user, err := s.userStore.GetUserByEmail(req.Email)
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Get user's passkeys
	credentials, err := s.passkeyStore.GetUserPasskeys(user.ID)
	if err != nil || len(credentials) == 0 {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Begin WebAuthn login
	options, sessionData, err := s.webauthn.BeginLogin(user, credentials)
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin login"})
		return
	}

	// Store session data and user ID in cookie (base64-encoded)
	sessionJSON, _ := json.Marshal(sessionData)
	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_session",
		Value:    base64.StdEncoding.EncodeToString(sessionJSON),
		MaxAge:   300,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "login_user_id",
		Value:    user.ID,
		MaxAge:   300,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	axon.WriteJSON(w, http.StatusOK, map[string]any{
		"options": options,
	})
}

type loginFinishRequest struct {
	Credential  map[string]interface{} `json:"credential"`
	CLIRedirect string                 `json:"cli_redirect,omitempty"`
	CLIMode     bool                   `json:"cli_mode,omitempty"`
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req loginFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Credential == nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "credential is required"})
		return
	}

	// Get session data from cookie
	sessionCookie, err := r.Cookie("webauthn_session")
	if err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no login session"})
		return
	}

	sessionJSON, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		slog.Error("login finish: session base64 decode failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session data"})
		return
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		slog.Error("login finish: session unmarshal failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session data"})
		return
	}

	// Get user ID
	userIDCookie, err := r.Cookie("login_user_id")
	if err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no user ID"})
		return
	}

	user, err := s.userStore.GetUserByID(userIDCookie.Value)
	if err != nil {
		slog.Error("login finish: user not found", "error", err, "user_id", userIDCookie.Value)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user not found"})
		return
	}

	// Get user's passkeys
	credentials, err := s.passkeyStore.GetUserPasskeys(user.ID)
	if err != nil {
		slog.Error("login finish: failed to get passkeys", "error", err)
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get passkeys"})
		return
	}

	// Parse credential
	credentialJSON, _ := json.Marshal(req.Credential)
	parsedCredential, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credentialJSON))
	if err != nil {
		slog.Error("login finish: credential parse failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid credential"})
		return
	}

	// Finish login
	credential, err := s.webauthn.FinishLogin(user, sessionData, parsedCredential, credentials)
	if err != nil {
		slog.Error("login finish: verification failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to verify credential"})
		return
	}

	// Update sign count
	s.passkeyStore.UpdateSignCount(credential.ID, credential.Authenticator.SignCount)

	// Create session
	token, tokenHash, err := GenerateToken()
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}

	session, err := s.sessionStore.CreateSession(user.ID, tokenHash, time.Now().Add(s.config.SessionDuration))
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		MaxAge:   int(s.config.SessionDuration.Seconds()),
		Path:     "/",
		Domain:   s.config.CookieDomain,
		Secure:   s.config.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear temporary cookies
	http.SetCookie(w, &http.Cookie{Name: "webauthn_session", Value: "", MaxAge: -1, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "login_user_id", Value: "", MaxAge: -1, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})

	response := map[string]any{
		"user_id":    user.ID,
		"session_id": session.ID,
	}
	if req.CLIMode || isLocalRedirect(req.CLIRedirect) {
		response["token"] = token
	}
	axon.WriteJSON(w, http.StatusOK, response)
}
