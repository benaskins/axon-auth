# CLAUDE.md

## Overview

axon-auth is a WebAuthn-based authentication library providing passkey registration, login, session management, and invite-based user onboarding. It defines store interfaces for persistence — PostgreSQL implementations live in the host application.

## Build & Test

```bash
go build ./...         # Build all packages
go test ./...          # Run all tests (no database needed)
go vet ./...           # Lint
```

All tests use in-memory mock stores from `authtest/` — no database required.

## Architecture

- **Store interfaces** (`store.go`): `UserStore`, `SessionStore`, `PasskeyStore`, `InviteStore`
- **Domain types** (`types.go`): `User`, `Session`, `Invite`
- **Token management** (`token.go`): `GenerateToken()`, `HashToken()` — SHA-256 hashed tokens
- **Server** (`server.go`): HTTP handler composition, routes API endpoints
- **Handlers**: One file per endpoint group (`handler_register.go`, `handler_login.go`, etc.)
- **WebAuthn** (`webauthn.go`): Wrapper around go-webauthn library
- **Config** (`config.go`): All hardcoded values externalized
- **Static files** (`embed.go`): Pre-built SvelteKit UI embedded via `//go:embed`
- **Mock stores** (`authtest/stores.go`): In-memory implementations for testing

## Key Design Decisions

- **No database imports**: This package has zero `database/sql` or driver dependencies
- **Token generation is business logic**: Handlers call `GenerateToken()` and pass hashes to stores
- **Sentinel errors**: `ErrDuplicateUsername`, `ErrNotFound` — postgres implementations wrap these
- **Config-driven**: Cookie domain, WebAuthn RP ID, origins all come from `Config` struct

## Dependencies

- `github.com/benaskins/axon` — HTTP helpers, SPA handler, middleware
- `github.com/go-webauthn/webauthn` — WebAuthn protocol
