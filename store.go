package auth

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type UserStore interface {
	CreateUser(ctx context.Context, id, username, email, passwordHash, displayName string, roles []string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	DeleteUser(ctx context.Context, id string) error
	UpdateUser(ctx context.Context, user *User) error
	SetUserRoles(ctx context.Context, userID string, roles []string) error
	// Deprecated: Use SetUserRoles instead
	SetAdmin(ctx context.Context, id string, isAdmin bool) error
}

type SessionStore interface {
	CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*Session, error)
	ValidateSessionByHash(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSessionByHash(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpiredSessions(ctx context.Context) error
}

type JWTTokenStore interface {
	CreateToken(ctx context.Context, userID, token string, expiresAt time.Time) (*JWTToken, error)
	ValidateToken(ctx context.Context, token string) (*JWTToken, error)
	DeleteToken(ctx context.Context, token string) error
	DeleteUserTokens(ctx context.Context, userID string) error
	CleanExpiredTokens(ctx context.Context) error
}

type PasskeyStore interface {
	SavePasskey(ctx context.Context, userID string, credential *webauthn.Credential, deviceName string) error
	GetUserPasskeys(ctx context.Context, userID string) ([]webauthn.Credential, error)
	UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	DeletePasskey(ctx context.Context, credentialID []byte) error
}

type InviteStore interface {
	CreateInvite(ctx context.Context, email, tokenHash string, expiresAt time.Time, isBootstrap bool) (*Invite, error)
	ValidateInviteByHash(ctx context.Context, tokenHash string) (*Invite, error)
	MarkInviteUsedByHash(ctx context.Context, tokenHash string) error
	CleanExpiredInvites(ctx context.Context) error
}

type PasswordResetStore interface {
	CreateResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*PasswordResetToken, error)
	ValidateResetTokenByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	MarkResetTokenUsedByHash(ctx context.Context, tokenHash string) error
	DeleteResetTokenByHash(ctx context.Context, tokenHash string) error
	CleanExpiredResetTokens(ctx context.Context) error
}
