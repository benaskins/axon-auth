package auth

import (
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnWrapper struct {
	webauthn *webauthn.WebAuthn
}

func NewWebAuthnWrapper(rpID, rpName string, rpOrigins []string) (*WebAuthnWrapper, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: rpName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
	}

	w, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn: %w", err)
	}

	return &WebAuthnWrapper{webauthn: w}, nil
}

// userWebAuthnEntity wraps User to implement webauthn.User interface.
type userWebAuthnEntity struct {
	user        *User
	credentials []webauthn.Credential
}

func (u *userWebAuthnEntity) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *userWebAuthnEntity) WebAuthnName() string {
	return u.user.Email
}

func (u *userWebAuthnEntity) WebAuthnDisplayName() string {
	return u.user.DisplayName
}

func (u *userWebAuthnEntity) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *userWebAuthnEntity) WebAuthnIcon() string {
	return ""
}

func (w *WebAuthnWrapper) BeginRegistration(user *User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	entity := &userWebAuthnEntity{user: user, credentials: []webauthn.Credential{}}
	return w.webauthn.BeginRegistration(entity)
}

func (w *WebAuthnWrapper) FinishRegistration(user *User, sessionData webauthn.SessionData, response *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	entity := &userWebAuthnEntity{user: user, credentials: []webauthn.Credential{}}
	return w.webauthn.CreateCredential(entity, sessionData, response)
}

func (w *WebAuthnWrapper) BeginLogin(user *User, credentials []webauthn.Credential) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	entity := &userWebAuthnEntity{user: user, credentials: credentials}
	return w.webauthn.BeginLogin(entity)
}

func (w *WebAuthnWrapper) FinishLogin(user *User, sessionData webauthn.SessionData, response *protocol.ParsedCredentialAssertionData, credentials []webauthn.Credential) (*webauthn.Credential, error) {
	entity := &userWebAuthnEntity{user: user, credentials: credentials}
	return w.webauthn.ValidateLogin(entity, sessionData, response)
}
