package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/benaskins/axon"
)

// Password login handler

type passwordLoginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	CLIRedirect string `json:"cli_redirect,omitempty"`
	CLIMode     bool   `json:"cli_mode,omitempty"`
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req passwordLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Email == "" || req.Password == "" {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password are required"})
		return
	}

	ctx := r.Context()

	// Get user by email
	user, err := s.userStore.GetUserByEmail(ctx, req.Email)
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Check if user has a password set
	if user.PasswordHash == "" {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "please use WebAuthn to login"})
		return
	}

	// Verify password
	if !CheckPasswordHash(req.Password, user.PasswordHash) {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userStore.UpdateUser(ctx, user); err != nil {
		slog.Error("password login: failed to update last login", "error", err)
	}

	// Create session
	token, tokenHash, err := GenerateToken()
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}

	session, err := s.sessionStore.CreateSession(ctx, user.ID, tokenHash, time.Now().Add(s.config.SessionDuration))
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

	response := map[string]any{
		"user_id":    user.ID,
		"session_id": session.ID,
	}
	if req.CLIMode || isLocalRedirect(req.CLIRedirect) {
		response["token"] = token
	}
	axon.WriteJSON(w, http.StatusOK, response)
}
