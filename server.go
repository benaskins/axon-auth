package auth

import (
	"embed"
	"encoding/json"
	"net/http"
	"time"

	"github.com/benaskins/axon"
	"github.com/google/uuid"
)

type Server struct {
	mux                *http.ServeMux
	config             Config
	userStore          UserStore
	sessionStore       SessionStore
	jwtTokenStore      JWTTokenStore
	passkeyStore       PasskeyStore
	inviteStore        InviteStore
	webauthn           *WebAuthnWrapper
	jwtManager         *JWTManager
	rateLimiter        *RateLimiter
	staticFiles        *embed.FS
}

func NewServer(cfg Config, users UserStore, sessions SessionStore, passkeys PasskeyStore, invites InviteStore, staticFiles *embed.FS) (*Server, error) {
	w, err := NewWebAuthnWrapper(cfg.RPID, cfg.RPDisplayName, cfg.RPOrigins)
	if err != nil {
		return nil, err
	}

	s := &Server{
		mux:          http.NewServeMux(),
		config:       cfg,
		userStore:    users,
		sessionStore: sessions,
		passkeyStore: passkeys,
		inviteStore:  invites,
		webauthn:     w,
		staticFiles:  staticFiles,
	}

	// Initialize JWT manager if secret is provided
	if cfg.JWTSecret != "" {
		s.jwtManager = NewJWTManager(cfg.JWTSecret)
	}

	// Initialize rate limiter if enabled
	if cfg.RateLimitEnabled {
		s.rateLimiter = NewRateLimiter(cfg.RateLimitRequests, cfg.RateLimitWindow)
	}

	s.setupRoutes()
	return s, nil
}

// NewServerWithJWT creates a server with JWT token store support
func NewServerWithJWT(cfg Config, users UserStore, sessions SessionStore, jwtTokens JWTTokenStore, passkeys PasskeyStore, invites InviteStore, staticFiles *embed.FS) (*Server, error) {
	s, err := NewServer(cfg, users, sessions, passkeys, invites, staticFiles)
	if err != nil {
		return nil, err
	}
	s.jwtTokenStore = jwtTokens
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) setupRoutes() {
	// WebAuthn routes
	s.mux.HandleFunc("GET /api/validate", s.handleValidate)
	s.mux.HandleFunc("POST /api/register/begin", s.handleRegistrationBegin)
	s.mux.HandleFunc("POST /api/register/finish", s.handleRegistrationFinish)
	s.mux.HandleFunc("POST /api/login/begin", s.handleLoginBegin)
	s.mux.HandleFunc("POST /api/login/finish", s.handleLoginFinish)

	// Password authentication routes
	s.mux.HandleFunc("POST /api/password/register", s.handlePasswordRegister)
	s.mux.HandleFunc("POST /api/password/login", s.handlePasswordLogin)
	s.mux.HandleFunc("POST /api/password/reset", s.handlePasswordResetRequest)

	// Session management
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("POST /api/refresh", s.handleRefreshToken)

	// User management
	s.mux.Handle("POST /internal/service-user", &serviceUserHandler{
		userStore:      s.userStore,
		sessionStore:   s.sessionStore,
		sessionTTL:     365 * 24 * time.Hour,
		internalAPIKey: s.config.InternalAPIKey,
	})

	// SPA handler
	if s.staticFiles != nil {
		s.mux.Handle("/", axon.SPAHandler(*s.staticFiles, "static"))
	}
}

// handleRefreshToken generates a new JWT token using an existing session
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if s.jwtManager == nil {
		axon.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "JWT not configured"})
		return
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "no session"})
		return
	}

	ctx := r.Context()
	session, err := s.sessionStore.ValidateSessionByHash(ctx, HashToken(cookie.Value))
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session"})
		return
	}

	user, err := s.userStore.GetUserByID(ctx, session.UserID)
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	// Generate new JWT token
	token, err := s.jwtManager.GenerateToken(user, s.config.JWTExpiration)
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
		return
	}

	axon.WriteJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(s.config.JWTExpiration.Seconds()),
	})
}

// handlePasswordRegister handles complete password registration
func (s *Server) handlePasswordRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Email == "" || req.Password == "" || req.Username == "" || req.DisplayName == "" {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email, password, username, and display_name are required"})
		return
	}

	// Validate password strength
	if err := ValidatePasswordStrength(req.Password); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Validate username format
	if len(req.Username) < 2 || len(req.Username) > 30 || !axon.ValidSlug.MatchString(req.Username) {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "username must be 2-30 lowercase alphanumeric characters (hyphens allowed between words)"})
		return
	}

	ctx := r.Context()

	// Check email uniqueness
	existingByEmail, _ := s.userStore.GetUserByEmail(ctx, req.Email)
	if existingByEmail != nil {
		axon.WriteJSON(w, http.StatusConflict, map[string]string{"error": "email already registered"})
		return
	}

	// Check username uniqueness
	existingByUsername, _ := s.userStore.GetUserByUsername(ctx, req.Username)
	if existingByUsername != nil {
		axon.WriteJSON(w, http.StatusConflict, map[string]string{"error": "username already taken"})
		return
	}

	// Hash password
	passwordHash, err := HashPassword(req.Password, s.config.PasswordBcryptCost)
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
		return
	}

	// Create user
	userID := uuid.New().String()
	roles := []string{string(RoleUser)}

	user, err := s.userStore.CreateUser(ctx, userID, req.Username, req.Email, passwordHash, req.DisplayName, roles)
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		return
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

	axon.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":    user.ID,
		"session_id": session.ID,
	})
}

// handlePasswordResetRequest initiates password reset
func (s *Server) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Email == "" {
		axon.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	ctx := r.Context()

	// Get user by email
	_, err := s.userStore.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Always return success to prevent email enumeration
		axon.WriteJSON(w, http.StatusOK, map[string]string{
			"message": "if the email exists, a reset link has been sent",
		})
		return
	}

	// Generate reset token (in production, this would be sent via email)
	token, _, err := GenerateToken()
	if err != nil {
		axon.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate reset token"})
		return
	}

	axon.WriteJSON(w, http.StatusOK, map[string]any{
		"message": "reset token generated (in production, this would be sent via email)",
		"token":   token, // Only for testing; in production, send via email
	})
}
