---
module: github.com/benaskins/axon-auth
kind: service
---

# axon-auth

## Overview

axon-auth is a comprehensive authentication library providing WebAuthn/passkey and email/password authentication, JWT sessions, session management, RBAC, rate limiting, and invite-based user onboarding. It defines store interfaces for persistence — PostgreSQL implementations live in the host application.

## Build & Test

```bash
go build ./...         # Build all packages
go test ./...          # Run all tests (no database needed)
go vet ./...           # Lint
```

All tests use in-memory mock stores from `authtest/` — no database required.

## Architecture

- **Store interfaces** (`store.go`): `UserStore`, `SessionStore`, `JWTTokenStore`, `PasskeyStore`, `InviteStore`, `PasswordResetStore`
- **Domain types** (`types.go`): `User`, `Session`, `JWTToken`, `Invite`, `PasswordResetToken`, `Role`
- **Token management** (`token.go`): `GenerateToken()`, `HashToken()` — SHA-256 hashed tokens for sessions
- **JWT management** (`jwt.go`): `JWTManager`, `JWTClaims` — JWT token generation and validation
- **Password utilities** (`password.go`): `HashPassword()`, `CheckPasswordHash()`, `ValidatePasswordStrength()`
- **Rate limiting** (`ratelimit.go`): `RateLimiter` — token bucket rate limiter
- **Middleware** (`middleware.go`): Session, JWT, RBAC, and rate limit middleware
- **Server** (`server.go`): HTTP handler composition, routes API endpoints
- **Handlers**: 
  - `handler_register.go` — WebAuthn registration
  - `handler_login.go` — WebAuthn login
  - `handler_password_login.go` — Password login
  - `handler_validate.go` — Session validation
  - `handler_logout.go` — Session logout
  - `handler_service_user.go` — Internal service user creation
- **Bootstrap** (`bootstrap.go`): `CreateBootstrapInvite`, `PrintBootstrapURL` — admin bootstrap invite creation
- **Helpers** (`helpers.go`): Internal utilities (e.g. `isLocalRedirect` for CLI auth)
- **WebAuthn** (`webauthn.go`): Wrapper around go-webauthn library
- **Config** (`config.go`): All hardcoded values externalized, `DefaultConfig()`
- **Errors** (`errors.go`): Sentinel errors for auth operations
- **Static files** (`embed.go`): Pre-built SvelteKit UI embedded via `//go:embed`
- **Mock stores** (`authtest/stores.go`): In-memory implementations for testing

## Authentication Methods

### WebAuthn/Passkeys
- Registration via invite token
- Login with registered passkeys
- Multiple devices per user

### Email/Password
- Registration with password strength validation
- Login with email and password
- Password reset functionality

### JWT Tokens
- Short-lived access tokens (default 15 minutes)
- Long-lived refresh tokens (default 7 days)
- Bearer token authentication via `Authorization` header

## RBAC (Role-Based Access Control)

Built-in roles:
- `RoleAdmin` — Full administrative access
- `RoleUser` — Standard user access
- `RoleModerator` — Moderation capabilities

Middleware:
- `RequireAuth()` — Require valid session or JWT
- `RequireRole(role)` — Require specific role
- `RequireAnyRole(roles...)` — Require any of specified roles

## Rate Limiting

Token bucket rate limiter with configurable:
- Maximum requests per window
- Time window duration
- Client identification via IP address

## Key Design Decisions

- **No database imports**: This package has zero `database/sql` or driver dependencies
- **Token generation is business logic**: Handlers call `GenerateToken()` and pass hashes to stores
- **Sentinel errors**: `ErrDuplicateUsername`, `ErrNotFound`, `ErrInvalidPassword`, etc.
- **Config-driven**: Cookie domain, WebAuthn RP ID, origins, JWT secret, rate limits all come from `Config` struct
- **Backward compatible**: `IsAdmin` field kept for compatibility, use `Roles` slice instead
- **Password hashing**: bcrypt with configurable cost (default 12)

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

### Internal
- `POST /internal/service-user` — Create service user (requires API key)

## Dependencies

- `github.com/benaskins/axon` — HTTP helpers, SPA handler, middleware
- `github.com/go-webauthn/webauthn` — WebAuthn protocol
- `golang.org/x/crypto/bcrypt` — Password hashing
- `github.com/golang-jwt/jwt/v5` — JWT token handling
- `github.com/google/uuid` — UUID generation
