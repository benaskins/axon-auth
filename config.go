package auth

import "time"

type Config struct {
	RPID            string
	RPDisplayName   string
	RPOrigins       []string
	CookieDomain    string
	SecureCookie    bool
	BaseURL         string
	SessionDuration time.Duration
	InviteDuration  time.Duration
}
