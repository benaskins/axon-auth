package auth

import (
	"embed"
	"net/http"
	"time"

	"github.com/benaskins/axon"
)

type Server struct {
	mux          *http.ServeMux
	config       Config
	userStore    UserStore
	sessionStore SessionStore
	passkeyStore PasskeyStore
	inviteStore  InviteStore
	webauthn     *WebAuthnWrapper
	staticFiles  *embed.FS
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

	s.setupRoutes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("GET /api/validate", s.handleValidate)
	s.mux.HandleFunc("POST /api/register/begin", s.handleRegistrationBegin)
	s.mux.HandleFunc("POST /api/register/finish", s.handleRegistrationFinish)
	s.mux.HandleFunc("POST /api/login/begin", s.handleLoginBegin)
	s.mux.HandleFunc("POST /api/login/finish", s.handleLoginFinish)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)

	s.mux.Handle("POST /internal/service-user", &serviceUserHandler{
		userStore:    s.userStore,
		sessionStore: s.sessionStore,
		sessionTTL:   365 * 24 * time.Hour,
	})

	if s.staticFiles != nil {
		s.mux.Handle("/", axon.SPAHandler(*s.staticFiles, "static"))
	}
}
