package auth

import "time"

// Role represents a user role for RBAC
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleUser    Role = "user"
	RoleModerator Role = "moderator"
)

// User represents an authenticated user in the system
type User struct {
	ID            string
	Username      string
	Email         string
	PasswordHash  string // bcrypt/argon2 hash for password auth (empty if WebAuthn-only)
	DisplayName   string
	Roles         []Role // RBAC roles
	IsAdmin       bool   // Deprecated: use Roles instead, kept for backward compatibility
	IsActive      bool   // Whether the account is active
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
}

// Session represents a session for cookie-based authentication
type Session struct {
	ID         string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// JWTToken represents a JWT-based session token
type JWTToken struct {
	ID        string
	UserID    string
	Token     string // The actual JWT token
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Invite represents an invitation for user onboarding
type Invite struct {
	ID          string
	Email       string
	TokenHash   string
	IsBootstrap bool
	Used        bool
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash string
	Used      bool
	CreatedAt time.Time
	ExpiresAt time.Time
}
