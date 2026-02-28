package auth

import (
	"testing"
)

func TestNewWebAuthnWrapper(t *testing.T) {
	wrapper, err := NewWebAuthnWrapper("auth.studio.internal", "Aurelia Auth", []string{"https://auth.studio.internal"})
	if err != nil {
		t.Fatalf("failed to create webauthn wrapper: %v", err)
	}

	if wrapper == nil {
		t.Error("wrapper is nil")
	}
}

func TestUserWebAuthnEntity(t *testing.T) {
	user := &User{
		ID:          "test-user-id",
		Email:       "test@example.com",
		DisplayName: "Test User",
	}

	entity := &userWebAuthnEntity{user: user}

	if string(entity.WebAuthnID()) != "test-user-id" {
		t.Errorf("expected ID test-user-id, got %s", entity.WebAuthnID())
	}

	if entity.WebAuthnName() != "test@example.com" {
		t.Errorf("expected name test@example.com, got %s", entity.WebAuthnName())
	}

	if entity.WebAuthnDisplayName() != "Test User" {
		t.Errorf("expected display name Test User, got %s", entity.WebAuthnDisplayName())
	}
}
