package auth

import (
	"context"
	"errors"
	"time"

	"github.com/benaskins/axon"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrNotFound         = axon.ErrNotFound
	ErrDuplicateUsername = errors.New("username already taken")
)

type UserStore interface {
	CreateUser(ctx context.Context, username, email, displayName string, isAdmin bool) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	DeleteUser(ctx context.Context, id string) error
	SetAdmin(ctx context.Context, id string, isAdmin bool) error
}

type SessionStore interface {
	CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (*Session, error)
	ValidateSessionByHash(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSessionByHash(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpiredSessions(ctx context.Context) error
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
