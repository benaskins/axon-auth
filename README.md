# axon-auth

> Domain package · Part of the [lamina](https://github.com/benaskins/lamina-mono) workspace

Comprehensive authentication library supporting WebAuthn/passkeys, email/password, JWT sessions, RBAC, and rate limiting. Defines store interfaces (`UserStore`, `SessionStore`, `JWTTokenStore`, `PasskeyStore`, `InviteStore`, `PasswordResetStore`) so any persistence backend can be plugged in. HTTP handlers are composed into a `Server` that mounts onto your existing mux.

## Getting started

```
go get github.com/benaskins/axon-auth@latest
```

axon-auth is a domain package — it provides types, interfaces, and HTTP handlers but no `main` function. You assemble it in your own composition root by supplying store implementations and configuration. See [`example/main.go`](example/main.go) for a minimal wiring example.

### Basic setup with default config

```go
cfg := auth.DefaultConfig()
cfg.RPID = "example.com"
cfg.RPDisplayName = "Example App"
cfg.RPOrigins = []string{"https://example.com"}
cfg.CookieDomain = ".example.com"
cfg.SecureCookie = true
cfg.JWTSecret = "your-secret-key" // Enable JWT support
cfg.RateLimitEnabled = true

// Use authtest stores for development; supply real implementations in production.
srv, err := auth.NewServer(cfg,
    authtest.NewMemoryUserStore(),
    authtest.NewMemorySessionStore(),
    authtest.NewMemoryPasskeyStore(),
    authtest.NewMemoryInviteStore(),
    nil, // optional embed.FS for static files
)
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/auth/", http.StripPrefix("/auth", srv.Handler()))
log.Fatal(http.ListenAndServe(":8080", mux))
```

### With JWT token store

```go
srv, err := auth.NewServerWithJWT(cfg,
    authtest.NewMemoryUserStore(),
    authtest.NewMemorySessionStore(),
    authtest.NewMemoryJWTTokenStore(),
    authtest.NewMemoryPasskeyStore(),
    authtest.NewMemoryInviteStore(),
    nil,
)
```

### Using middleware

```go
// Require authentication
mux.Handle("/protected/", auth.RequireAuth(userStore, sessionStore, jwtManager)(yourHandler))

// Require specific role
mux.Handle("/admin/", auth.RequireRole(auth.RoleAdmin)(adminHandler))

// Rate limiting
limiter := auth.NewRateLimiter(100, time.Minute)
mux.Handle("/api/", auth.RateLimitMiddleware(limiter, apiHandler))
```

## Key types

- **`Config`** — relying party ID, origins, cookie domain, session/invite durations, JWT settings, rate limiting
- **`DefaultConfig()`** — returns config with sensible defaults
- **`Server`** — HTTP handler with registration, login, validation, logout, and password endpoints
- **`User`**, **`Session`**, **`JWTToken`**, **`Invite`**, **`PasswordResetToken`** — domain types
- **`Role`** — RBAC roles (Admin, User, Moderator)
- **`UserStore`**, **`SessionStore`**, **`JWTTokenStore`**, **`PasskeyStore`**, **`InviteStore`**, **`PasswordResetStore`** — persistence interfaces
- **`JWTManager`** — JWT token generation and validation
- **`RateLimiter`** — token bucket rate limiter
- **`WebAuthnWrapper`** — WebAuthn protocol wrapper around go-webauthn
- **`authtest`** — in-memory mock stores for testing

## Authentication methods

### WebAuthn/Passkeys
- Passwordless authentication with biometrics/security keys
- Multiple devices per user
- Invite-based registration

### Email/Password
- Bcrypt password hashing (configurable cost)
- Password strength validation
- Password reset functionality

### JWT Tokens
- Short-lived access tokens
- Long-lived refresh tokens
- Bearer token authentication

## API Endpoints

### WebAuthn
- `POST /api/register/begin` — Begin WebAuthn registration
- `POST /api/register/finish` — Complete WebAuthn registration
- `POST /api/login/begin` — Begin WebAuthn login
- `POST /api/login/finish` — Complete WebAuthn login

### Password Authentication
- `POST /api/password/register` — Register with email/password
- `POST /api/password/login` — Login with email/password
- `POST /api/password/reset` — Request password reset

### Session Management
- `GET /api/validate` — Validate current session
- `POST /api/logout` — Logout (invalidate session)
- `POST /api/refresh` — Refresh JWT token

## License

MIT
