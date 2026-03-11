package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// CreateBootstrapInvite creates an admin bootstrap invite for the given email.
// It returns the plaintext token for use in a registration URL.
func CreateBootstrapInvite(ctx context.Context, invites InviteStore, email string, duration time.Duration) (string, error) {
	token, hash, err := GenerateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	invite, err := invites.CreateInvite(ctx, email, hash, time.Now().Add(duration), true)
	if err != nil {
		return "", fmt.Errorf("failed to create bootstrap invite: %w", err)
	}

	slog.Info("bootstrap invite created",
		"email", email,
		"id", invite.ID,
		"expires", invite.ExpiresAt.Format(time.RFC3339))

	return token, nil
}

// PrintBootstrapURL prints the registration URL for a bootstrap invite.
func PrintBootstrapURL(baseURL, token string) {
	regURL := fmt.Sprintf("%s/register?token=%s", baseURL, token)
	separator := strings.Repeat("=", 80)
	fmt.Println("\n" + separator)
	fmt.Println("BOOTSTRAP ADMIN USER")
	fmt.Println(separator)
	fmt.Println("\nRegistration URL:")
	fmt.Println(regURL)
	fmt.Println("\nThis invite expires in 24 hours.")
	fmt.Println("The first user to register will automatically become an admin.")
	fmt.Println(separator + "\n")
}
