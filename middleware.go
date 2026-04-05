package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/benaskins/axon"
)

// Context keys for middleware
type contextKey string

const (
	UserContextKey       contextKey = "user"
	JWTClaimsContextKey  contextKey = "jwt_claims"
	SessionContextKey    contextKey = "session"
)

// UserFromContext extracts the user from context
func UserFromContext(ctx context.Context) *User {
	if u, ok := ctx.Value(UserContextKey).(*User); ok {
		return u
	}
	return nil
}

// JWTClaimsFromContext extracts JWT claims from context
func JWTClaimsFromContext(ctx context.Context) *JWTClaims {
	if c, ok := ctx.Value(JWTClaimsContextKey).(*JWTClaims); ok {
		return c
	}
	return nil
}

// SessionMiddleware validates session cookies and adds user to context
func SessionMiddleware(sessionStore SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		session, err := sessionStore.ValidateSessionByHash(r.Context(), HashToken(cookie.Value))
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// User will be loaded by the handler if needed
		ctx := context.WithValue(r.Context(), SessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// JWTMiddleware validates JWT tokens and adds claims to context
func JWTMiddleware(jwtManager *JWTManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := jwtManager.ValidateToken(parts[1])
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), JWTClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuth middleware requires a valid session or JWT
func RequireAuth(userStore UserStore, sessionStore SessionStore, jwtManager *JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var user *User
			var err error

			// Try JWT first
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && parts[0] == "Bearer" {
					claims, err := jwtManager.ValidateToken(parts[1])
					if err == nil {
						user, err = userStore.GetUserByID(r.Context(), claims.UserID)
					}
				}
			}

			// Try session cookie if JWT failed
			if user == nil {
				cookie, err := r.Cookie("session")
				if err == nil {
					session, err := sessionStore.ValidateSessionByHash(r.Context(), HashToken(cookie.Value))
					if err == nil {
						user, err = userStore.GetUserByID(r.Context(), session.UserID)
					}
				}
			}

			if err != nil || user == nil {
				axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole middleware requires the user to have a specific role
func RequireRole(requiredRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}

			// Check if user has the required role
			hasRole := false
			for _, role := range user.Roles {
				if role == requiredRole {
					hasRole = true
					break
				}
			}

			// Fallback to IsAdmin for backward compatibility
			if !hasRole && user.IsAdmin {
				hasRole = true
			}

			if !hasRole {
				axon.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole middleware requires the user to have any of the specified roles
func RequireAnyRole(roles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				axon.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}

			hasRole := false
			for _, required := range roles {
				for _, role := range user.Roles {
					if role == required {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			// Fallback to IsAdmin for backward compatibility
			if !hasRole && user.IsAdmin {
				hasRole = true
			}

			if !hasRole {
				axon.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware limits requests per client
func RateLimitMiddleware(limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := IPKey(r)

		if !limiter.Allow(key) {
			w.Header().Set("X-RateLimit-Limit", "100")
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "60")
			w.Header().Set("Retry-After", "60")
			axon.WriteJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
			return
		}

		remaining := limiter.GetRemaining(key)
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", string(rune('0' + remaining)))
		
		next.ServeHTTP(w, r)
	})
}
