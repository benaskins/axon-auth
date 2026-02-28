package auth

import (
	"net/http"

	"github.com/benaskins/axon"
)

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "no session cookie"})
		return
	}

	tokenHash := HashToken(cookie.Value)
	session, err := s.sessionStore.ValidateSessionByHash(tokenHash)
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session"})
		return
	}

	user, err := s.userStore.GetUserByID(session.UserID)
	if err != nil {
		axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	axon.WriteJSON(w, http.StatusOK, map[string]any{
		"user_id":      user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"is_admin":     user.IsAdmin,
	})
}
