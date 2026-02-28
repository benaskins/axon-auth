package auth

import (
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrDuplicateUsername = errors.New("username already taken")
)

type UserStore interface {
	CreateUser(username, email, displayName string, isAdmin bool) (*User, error)
	GetUserByEmail(email string) (*User, error)
	GetUserByUsername(username string) (*User, error)
	GetUserByID(id string) (*User, error)
	ListUsers() ([]*User, error)
	DeleteUser(id string) error
	SetAdmin(id string, isAdmin bool) error
}

type SessionStore interface {
	CreateSession(userID, tokenHash string, expiresAt time.Time) (*Session, error)
	ValidateSessionByHash(tokenHash string) (*Session, error)
	DeleteSessionByHash(tokenHash string) error
	DeleteUserSessions(userID string) error
	CleanExpiredSessions() error
}

type PasskeyStore interface {
	SavePasskey(userID string, credential *webauthn.Credential, deviceName string) error
	GetUserPasskeys(userID string) ([]webauthn.Credential, error)
	UpdateSignCount(credentialID []byte, signCount uint32) error
	DeletePasskey(credentialID []byte) error
}

type InviteStore interface {
	CreateInvite(email, tokenHash string, expiresAt time.Time, isBootstrap bool) (*Invite, error)
	ValidateInviteByHash(tokenHash string) (*Invite, error)
	MarkInviteUsedByHash(tokenHash string) error
	CleanExpiredInvites() error
}
