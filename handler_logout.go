package auth

import (
	"net/http"

	"github.com/benaskins/axon"
)

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		axon.WriteJSON(w, http.StatusOK, map[string]string{"message": "no session"})
		return
	}

	tokenHash := HashToken(cookie.Value)
	s.sessionStore.DeleteSessionByHash(tokenHash)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		Domain:   s.config.CookieDomain,
		Secure:   s.config.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	axon.WriteJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}
