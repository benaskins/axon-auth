package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/benaskins/axon"
)

type serviceUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type serviceUserResponse struct {
	UserID       string `json:"user_id"`
	SessionToken string `json:"session_token"`
}

type serviceUserHandler struct {
	userStore      UserStore
	sessionStore   SessionStore
	sessionTTL     time.Duration
	internalAPIKey string
}

func (h *serviceUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Require a valid internal API key
	apiKey := r.Header.Get("X-Internal-API-Key")
	if h.internalAPIKey == "" ||
		subtle.ConstantTimeCompare([]byte(apiKey), []byte(h.internalAPIKey)) != 1 {
		axon.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req serviceUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		axon.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" {
		axon.WriteError(w, http.StatusBadRequest, "username is required")
		return
	}

	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}

	ctx := r.Context()

	// Idempotent: look up existing user first
	user, err := h.userStore.GetUserByUsername(ctx, req.Username)
	if errors.Is(err, ErrNotFound) {
		// Create new service user (no passkey, no invite)
		email := req.Username + "@service.internal"
		user, err = h.userStore.CreateUser(ctx, req.Username, email, req.DisplayName, false)
		if err != nil {
			slog.Error("service-user: failed to create user", "error", err)
			axon.WriteError(w, http.StatusInternalServerError, "failed to create user")
			return
		}
		slog.Info("service-user: created", "user_id", user.ID, "username", req.Username)
	} else if err != nil {
		slog.Error("service-user: failed to look up user", "error", err)
		axon.WriteError(w, http.StatusInternalServerError, "failed to look up user")
		return
	}

	// Mint a long-lived session token
	token, tokenHash, err := GenerateToken()
	if err != nil {
		slog.Error("service-user: failed to generate token", "error", err)
		axon.WriteError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	_, err = h.sessionStore.CreateSession(ctx, user.ID, tokenHash, time.Now().Add(h.sessionTTL))
	if err != nil {
		slog.Error("service-user: failed to create session", "error", err)
		axon.WriteError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	axon.WriteJSON(w, http.StatusOK, serviceUserResponse{
		UserID:       user.ID,
		SessionToken: token,
	})
}
