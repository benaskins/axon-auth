package auth_test

import (
	"testing"
	"time"

	auth "github.com/benaskins/axon-auth"
	"github.com/benaskins/axon-auth/authtest"
)

func TestCreateBootstrapInvite(t *testing.T) {
	invites := authtest.NewMemoryInviteStore()

	token, err := auth.CreateBootstrapInvite(invites, "admin@example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create bootstrap invite: %v", err)
	}

	if token == "" {
		t.Error("token is empty")
	}

	// Validate invite by hashing the token
	hash := auth.HashToken(token)
	invite, err := invites.ValidateInviteByHash(hash)
	if err != nil {
		t.Fatalf("failed to validate invite: %v", err)
	}

	if invite.Email != "admin@example.com" {
		t.Errorf("expected email admin@example.com, got %s", invite.Email)
	}
	if !invite.IsBootstrap {
		t.Error("invite should be bootstrap")
	}
}
