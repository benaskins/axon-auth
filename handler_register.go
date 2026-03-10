package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/benaskins/axon"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type registrationBeginRequest struct {
	Token       string `json:"token"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

func (s *Server) handleRegistrationBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req registrationBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Token == "" || req.Username == "" || req.DisplayName == "" {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "token, username, and display_name are required"})
		return
	}

	// Validate username format
	if len(req.Username) < 2 || len(req.Username) > 30 || !axon.ValidSlug.MatchString(req.Username) {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "username must be 2-30 lowercase alphanumeric characters (hyphens allowed between words)"})
		return
	}

	// Check username uniqueness
	existingByUsername, _ := s.userStore.GetUserByUsername(req.Username)
	if existingByUsername != nil {
		axon.WriteJSON(w, http.StatusConflict, map[string]string{"error": "username already taken"})
		return
	}

	// Validate invite
	tokenHash := HashToken(req.Token)
	invite, err := s.inviteStore.ValidateInviteByHash(tokenHash)
	if err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired invite"})
		return
	}

	// Check if user already exists for this invite email
	existingUser, _ := s.userStore.GetUserByEmail(invite.Email)
	if existingUser != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user already exists"})
		return
	}

	// Build a temporary user for the WebAuthn ceremony (not persisted yet).
	// The actual user record is created in the finish step after the browser
	// completes the credential creation, avoiding orphaned rows if the
	// browser crashes between begin and finish.
	tempUser := &User{
		ID:          invite.Email, // deterministic placeholder
		Username:    req.Username,
		Email:       invite.Email,
		DisplayName: req.DisplayName,
		IsAdmin:     invite.IsBootstrap,
	}

	// Begin WebAuthn registration
	options, sessionData, err := s.webauthn.BeginRegistration(tempUser)
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin registration"})
		return
	}

	// Store session data in cookie (base64-encoded to avoid cookie value escaping issues)
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

	// Store invite token for finish step
	http.SetCookie(w, &http.Cookie{
		Name:     "invite_token",
		Value:    req.Token,
		MaxAge:   300,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})

	// Store username and display_name for finish step
	regMeta, _ := json.Marshal(map[string]string{
		"username":     req.Username,
		"display_name": req.DisplayName,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "registration_meta",
		Value:    base64.StdEncoding.EncodeToString(regMeta),
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

type registrationFinishRequest struct {
	Credential map[string]interface{} `json:"credential"`
	DeviceName string                 `json:"device_name"`
}

func (s *Server) handleRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req registrationFinishRequest
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
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no registration session"})
		return
	}

	sessionJSON, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		slog.Error("registration finish: session base64 decode failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session data"})
		return
	}
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		slog.Error("registration finish: session unmarshal failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session data"})
		return
	}

	// Get invite token
	inviteTokenCookie, err := r.Cookie("invite_token")
	if err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no invite token"})
		return
	}

	inviteTokenHash := HashToken(inviteTokenCookie.Value)
	invite, err := s.inviteStore.ValidateInviteByHash(inviteTokenHash)
	if err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid invite"})
		return
	}

	// Retrieve registration metadata (username, display_name) from cookie
	regMetaCookie, err := r.Cookie("registration_meta")
	if err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no registration metadata"})
		return
	}
	regMetaJSON, err := base64.StdEncoding.DecodeString(regMetaCookie.Value)
	if err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid registration metadata"})
		return
	}
	var regMeta struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if err := json.Unmarshal(regMetaJSON, &regMeta); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid registration metadata"})
		return
	}

	// Build temporary user for WebAuthn verification (matches begin step)
	tempUser := &User{
		ID:          invite.Email,
		Username:    regMeta.Username,
		Email:       invite.Email,
		DisplayName: regMeta.DisplayName,
		IsAdmin:     invite.IsBootstrap,
	}

	// Parse credential
	credentialJSON, _ := json.Marshal(req.Credential)
	parsedCredential, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credentialJSON))
	if err != nil {
		slog.Error("registration finish: credential parse failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid credential"})
		return
	}

	// Finish registration (verify credential against the temporary user)
	credential, err := s.webauthn.FinishRegistration(tempUser, sessionData, parsedCredential)
	if err != nil {
		slog.Error("registration finish: verification failed", "error", err)
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to verify credential"})
		return
	}

	// WebAuthn verification succeeded — now create the real user record
	user, err := s.userStore.CreateUser(regMeta.Username, invite.Email, regMeta.DisplayName, invite.IsBootstrap)
	if err != nil {
		if errors.Is(err, ErrDuplicateUsername) {
			axon.WriteJSON(w, http.StatusConflict, map[string]string{"error": "username already taken"})
			return
		}
		slog.Error("registration finish: failed to create user", "error", err)
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		return
	}

	// Save passkey
	deviceName := req.DeviceName
	if deviceName == "" {
		deviceName = "Unknown Device"
	}
	if err := s.passkeyStore.SavePasskey(user.ID, credential, deviceName); err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save passkey"})
		return
	}

	// Mark invite as used
	if err := s.inviteStore.MarkInviteUsedByHash(inviteTokenHash); err != nil {
		slog.Error("registration finish: failed to mark invite used", "error", err)
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to finalize registration"})
		return
	}

	// Create session
	token, sessionTokenHash, err := GenerateToken()
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}

	session, err := s.sessionStore.CreateSession(user.ID, sessionTokenHash, time.Now().Add(s.config.SessionDuration))
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
	http.SetCookie(w, &http.Cookie{Name: "webauthn_session", Value: "", MaxAge: -1, Path: "/", HttpOnly: true, Secure: s.config.SecureCookie, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "invite_token", Value: "", MaxAge: -1, Path: "/", HttpOnly: true, Secure: s.config.SecureCookie, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "registration_meta", Value: "", MaxAge: -1, Path: "/", HttpOnly: true, Secure: s.config.SecureCookie, SameSite: http.SameSiteLaxMode})

	axon.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":    user.ID,
		"session_id": session.ID,
	})
}
