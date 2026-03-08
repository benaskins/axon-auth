//go:build ignore

package main

import (
	"log"
	"net/http"
	"time"

	auth "github.com/benaskins/axon-auth"
	"github.com/benaskins/axon-auth/authtest"
)

func main() {
	cfg := auth.Config{
		RPID:            "example.com",
		RPDisplayName:   "Example App",
		RPOrigins:       []string{"https://example.com"},
		CookieDomain:    ".example.com",
		SecureCookie:    true,
		SessionDuration: 24 * time.Hour,
		InviteDuration:  7 * 24 * time.Hour,
	}

	// In production, replace these with real store implementations
	// backed by PostgreSQL or another database.
	users := authtest.NewMemoryUserStore()
	sessions := authtest.NewMemorySessionStore()
	passkeys := authtest.NewMemoryPasskeyStore()
	invites := authtest.NewMemoryInviteStore()

	srv, err := auth.NewServer(cfg, users, sessions, passkeys, invites, nil)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", srv.Handler()))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
