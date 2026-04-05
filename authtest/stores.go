// Package authtest provides in-memory mock implementations of auth store
// interfaces for testing without a database.
package authtest

import (
	"context"
	"fmt"
	"sync"
	"time"

	auth "github.com/benaskins/axon-auth"

	"github.com/go-webauthn/webauthn/webauthn"
)

// MemoryUserStore is an in-memory implementation of auth.UserStore.
type MemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*auth.User // keyed by ID
	seq   int
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{users: make(map[string]*auth.User)}
}

func (s *MemoryUserStore) CreateUser(_ context.Context, id, username, email, passwordHash, displayName string, roles []string) (*auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check username uniqueness
	for _, u := range s.users {
		if u.Username == username {
			return nil, auth.ErrDuplicateUsername
		}
		if u.Email == email {
			return nil, auth.ErrDuplicateEmail
		}
	}

	if id == "" {
		s.seq++
		id = fmt.Sprintf("user-%d", s.seq)
	}
	now := time.Now()
	
	// Convert roles to Role slice
	roleSlice := make([]auth.Role, len(roles))
	isAdmin := false
	for i, r := range roles {
		roleSlice[i] = auth.Role(r)
		if auth.Role(r) == auth.RoleAdmin {
			isAdmin = true
		}
	}

	user := &auth.User{
		ID:            id,
		Username:      username,
		Email:         email,
		PasswordHash:  passwordHash,
		DisplayName:   displayName,
		Roles:         roleSlice,
		IsAdmin:       isAdmin,
		IsActive:      true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	s.users[id] = user
	return copyUser(user), nil
}

func (s *MemoryUserStore) GetUserByEmail(_ context.Context, email string) (*auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if u.Email == email {
			return copyUser(u), nil
		}
	}
	return nil, auth.ErrNotFound
}

func (s *MemoryUserStore) GetUserByUsername(_ context.Context, username string) (*auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if u.Username == username {
			return copyUser(u), nil
		}
	}
	return nil, auth.ErrNotFound
}

func (s *MemoryUserStore) GetUserByID(_ context.Context, id string) (*auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return copyUser(u), nil
}

func (s *MemoryUserStore) ListUsers(_ context.Context) ([]*auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var users []*auth.User
	for _, u := range s.users {
		users = append(users, copyUser(u))
	}
	return users, nil
}

func (s *MemoryUserStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	return nil
}

func (s *MemoryUserStore) UpdateUser(_ context.Context, user *auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.users[user.ID]
	if !ok {
		return auth.ErrNotFound
	}
	user.UpdatedAt = time.Now()
	s.users[user.ID] = copyUser(user)
	return nil
}

func (s *MemoryUserStore) SetUserRoles(_ context.Context, userID string, roles []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[userID]
	if !ok {
		return auth.ErrNotFound
	}

	roleSlice := make([]auth.Role, len(roles))
	isAdmin := false
	for i, r := range roles {
		roleSlice[i] = auth.Role(r)
		if auth.Role(r) == auth.RoleAdmin {
			isAdmin = true
		}
	}
	
	u.Roles = roleSlice
	u.IsAdmin = isAdmin
	u.UpdatedAt = time.Now()
	return nil
}

// SetAdmin is deprecated, use SetUserRoles instead
func (s *MemoryUserStore) SetAdmin(_ context.Context, id string, isAdmin bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return auth.ErrNotFound
	}
	u.IsAdmin = isAdmin
	if isAdmin {
		u.Roles = []auth.Role{auth.RoleAdmin}
	}
	u.UpdatedAt = time.Now()
	return nil
}

func copyUser(u *auth.User) *auth.User {
	c := *u
	c.Roles = make([]auth.Role, len(u.Roles))
	copy(c.Roles, u.Roles)
	return &c
}

// MemorySessionStore is an in-memory implementation of auth.SessionStore.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*auth.Session // keyed by token hash
	seq      int
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]*auth.Session)}
}

func (s *MemorySessionStore) CreateSession(_ context.Context, userID, tokenHash string, expiresAt time.Time) (*auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	now := time.Now()
	session := &auth.Session{
		ID:         fmt.Sprintf("session-%d", s.seq),
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
		LastUsedAt: now,
	}
	s.sessions[tokenHash] = session
	return copySession(session), nil
}

func (s *MemorySessionStore) ValidateSessionByHash(_ context.Context, tokenHash string) (*auth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[tokenHash]
	if !ok || session.ExpiresAt.Before(time.Now()) {
		return nil, auth.ErrNotFound
	}
	return copySession(session), nil
}

func (s *MemorySessionStore) DeleteSessionByHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenHash)
	return nil
}

func (s *MemorySessionStore) DeleteUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, hash)
		}
	}
	return nil
}

func (s *MemorySessionStore) CleanExpiredSessions(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for hash, session := range s.sessions {
		if session.ExpiresAt.Before(now) {
			delete(s.sessions, hash)
		}
	}
	return nil
}

func copySession(s *auth.Session) *auth.Session {
	c := *s
	return &c
}

// MemoryJWTTokenStore is an in-memory implementation of auth.JWTTokenStore.
type MemoryJWTTokenStore struct {
	mu    sync.RWMutex
	tokens map[string]*auth.JWTToken // keyed by token
	seq   int
}

func NewMemoryJWTTokenStore() *MemoryJWTTokenStore {
	return &MemoryJWTTokenStore{tokens: make(map[string]*auth.JWTToken)}
}

func (s *MemoryJWTTokenStore) CreateToken(_ context.Context, userID, token string, expiresAt time.Time) (*auth.JWTToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	now := time.Now()
	jwtToken := &auth.JWTToken{
		ID:        fmt.Sprintf("jwt-%d", s.seq),
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	s.tokens[token] = jwtToken
	return copyJWTToken(jwtToken), nil
}

func (s *MemoryJWTTokenStore) ValidateToken(_ context.Context, token string) (*auth.JWTToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jwtToken, ok := s.tokens[token]
	if !ok || jwtToken.ExpiresAt.Before(time.Now()) {
		return nil, auth.ErrNotFound
	}
	return copyJWTToken(jwtToken), nil
}

func (s *MemoryJWTTokenStore) DeleteToken(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

func (s *MemoryJWTTokenStore) DeleteUserTokens(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, jwtToken := range s.tokens {
		if jwtToken.UserID == userID {
			delete(s.tokens, hash)
		}
	}
	return nil
}

func (s *MemoryJWTTokenStore) CleanExpiredTokens(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for hash, jwtToken := range s.tokens {
		if jwtToken.ExpiresAt.Before(now) {
			delete(s.tokens, hash)
		}
	}
	return nil
}

func copyJWTToken(t *auth.JWTToken) *auth.JWTToken {
	c := *t
	return &c
}

// MemoryPasskeyStore is an in-memory implementation of auth.PasskeyStore.
type MemoryPasskeyStore struct {
	mu       sync.RWMutex
	passkeys map[string][]webauthn.Credential // keyed by user ID
}

func NewMemoryPasskeyStore() *MemoryPasskeyStore {
	return &MemoryPasskeyStore{passkeys: make(map[string][]webauthn.Credential)}
}

func (s *MemoryPasskeyStore) SavePasskey(_ context.Context, userID string, credential *webauthn.Credential, deviceName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.passkeys[userID] = append(s.passkeys[userID], *credential)
	return nil
}

func (s *MemoryPasskeyStore) GetUserPasskeys(_ context.Context, userID string) ([]webauthn.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds := s.passkeys[userID]
	result := make([]webauthn.Credential, len(creds))
	copy(result, creds)
	return result, nil
}

func (s *MemoryPasskeyStore) UpdateSignCount(_ context.Context, credentialID []byte, signCount uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for userID, creds := range s.passkeys {
		for i, c := range creds {
			if string(c.ID) == string(credentialID) {
				s.passkeys[userID][i].Authenticator.SignCount = signCount
				return nil
			}
		}
	}
	return nil
}

func (s *MemoryPasskeyStore) DeletePasskey(_ context.Context, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for userID, creds := range s.passkeys {
		for i, c := range creds {
			if string(c.ID) == string(credentialID) {
				s.passkeys[userID] = append(creds[:i], creds[i+1:]...)
				return nil
			}
		}
	}
	return nil
}

// MemoryInviteStore is an in-memory implementation of auth.InviteStore.
type MemoryInviteStore struct {
	mu      sync.RWMutex
	invites map[string]*auth.Invite // keyed by token hash
	seq     int
}

func NewMemoryInviteStore() *MemoryInviteStore {
	return &MemoryInviteStore{invites: make(map[string]*auth.Invite)}
}

func (s *MemoryInviteStore) CreateInvite(_ context.Context, email, tokenHash string, expiresAt time.Time, isBootstrap bool) (*auth.Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	now := time.Now()
	invite := &auth.Invite{
		ID:          fmt.Sprintf("invite-%d", s.seq),
		Email:       email,
		TokenHash:   tokenHash,
		IsBootstrap: isBootstrap,
		Used:        false,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}
	s.invites[tokenHash] = invite
	return copyInvite(invite), nil
}

func (s *MemoryInviteStore) ValidateInviteByHash(_ context.Context, tokenHash string) (*auth.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	invite, ok := s.invites[tokenHash]
	if !ok || invite.Used || invite.ExpiresAt.Before(time.Now()) {
		return nil, auth.ErrNotFound
	}
	return copyInvite(invite), nil
}

func (s *MemoryInviteStore) MarkInviteUsedByHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	invite, ok := s.invites[tokenHash]
	if !ok {
		return auth.ErrNotFound
	}
	invite.Used = true
	return nil
}

func (s *MemoryInviteStore) CleanExpiredInvites(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for hash, invite := range s.invites {
		if invite.ExpiresAt.Before(now) {
			delete(s.invites, hash)
		}
	}
	return nil
}

func copyInvite(i *auth.Invite) *auth.Invite {
	c := *i
	return &c
}

// MemoryPasswordResetStore is an in-memory implementation of auth.PasswordResetStore.
type MemoryPasswordResetStore struct {
	mu    sync.RWMutex
	tokens map[string]*auth.PasswordResetToken // keyed by token hash
	seq   int
}

func NewMemoryPasswordResetStore() *MemoryPasswordResetStore {
	return &MemoryPasswordResetStore{tokens: make(map[string]*auth.PasswordResetToken)}
}

func (s *MemoryPasswordResetStore) CreateResetToken(_ context.Context, userID, tokenHash string, expiresAt time.Time) (*auth.PasswordResetToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	now := time.Now()
	resetToken := &auth.PasswordResetToken{
		ID:        fmt.Sprintf("reset-%d", s.seq),
		UserID:    userID,
		TokenHash: tokenHash,
		Used:      false,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	s.tokens[tokenHash] = resetToken
	return copyResetToken(resetToken), nil
}

func (s *MemoryPasswordResetStore) ValidateResetTokenByHash(_ context.Context, tokenHash string) (*auth.PasswordResetToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resetToken, ok := s.tokens[tokenHash]
	if !ok || resetToken.Used || resetToken.ExpiresAt.Before(time.Now()) {
		return nil, auth.ErrNotFound
	}
	return copyResetToken(resetToken), nil
}

func (s *MemoryPasswordResetStore) MarkResetTokenUsedByHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	resetToken, ok := s.tokens[tokenHash]
	if !ok {
		return auth.ErrNotFound
	}
	resetToken.Used = true
	return nil
}

func (s *MemoryPasswordResetStore) DeleteResetTokenByHash(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tokenHash)
	return nil
}

func (s *MemoryPasswordResetStore) CleanExpiredResetTokens(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for hash, resetToken := range s.tokens {
		if resetToken.ExpiresAt.Before(now) {
			delete(s.tokens, hash)
		}
	}
	return nil
}

func copyResetToken(t *auth.PasswordResetToken) *auth.PasswordResetToken {
	c := *t
	return &c
}
