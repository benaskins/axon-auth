package auth

import "time"

type Config struct {
	// WebAuthn configuration
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	
	// Cookie configuration
	CookieDomain  string
	SecureCookie  bool
	BaseURL       string
	
	// Session configuration
	SessionDuration time.Duration
	
	// JWT configuration
	JWTSecret            string
	JWTExpiration        time.Duration
	JWTRefreshExpiration time.Duration
	
	// Invite configuration
	InviteDuration time.Duration
	
	// API configuration
	InternalAPIKey string
	
	// Rate limiting configuration
	RateLimitEnabled   bool
	RateLimitRequests  int  // Number of requests allowed
	RateLimitWindow    time.Duration // Time window for rate limiting
	
	// Password configuration
	PasswordMinLength  int
	PasswordBcryptCost int
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		SessionDuration:    24 * time.Hour,
		JWTExpiration:      15 * time.Minute,
		JWTRefreshExpiration: 7 * 24 * time.Hour,
		InviteDuration:     24 * time.Hour,
		RateLimitRequests:  100,
		RateLimitWindow:    time.Minute,
		PasswordMinLength:  8,
		PasswordBcryptCost: 12,
	}
}
