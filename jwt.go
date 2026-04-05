package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	IsAdmin   bool     `json:"is_admin"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token generation and validation
type JWTManager struct {
	secret []byte
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secret string) *JWTManager {
	return &JWTManager{
		secret: []byte(secret),
	}
}

// GenerateToken creates a new JWT token for a user
func (m *JWTManager) GenerateToken(user *User, expiration time.Duration) (string, error) {
	now := time.Now()
	expiry := now.Add(expiration)

	claims := JWTClaims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    make([]string, len(user.Roles)),
		IsAdmin:  user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "axon-auth",
			Subject:   user.ID,
		},
	}

	// Convert roles to strings
	for i, role := range user.Roles {
		claims.Roles[i] = string(role)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// GenerateRefreshToken creates a long-lived refresh token
func (m *JWTManager) GenerateRefreshToken(user *User) (string, error) {
	return m.GenerateToken(user, 7*24*time.Hour)
}

// ValidateToken parses and validates a JWT token
func (m *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// HasRole checks if the claims contain a specific role
func (c *JWTClaims) HasRole(role Role) bool {
	for _, r := range c.Roles {
		if Role(r) == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the claims contain any of the specified roles
func (c *JWTClaims) HasAnyRole(roles ...Role) bool {
	for _, required := range roles {
		if c.HasRole(required) {
			return true
		}
	}
	return false
}
