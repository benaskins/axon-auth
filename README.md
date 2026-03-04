# axon-auth

A WebAuthn-based authentication library with passkey registration, login, session management, and invite-based user onboarding.

Defines store interfaces for persistence, allowing any backend (PostgreSQL, in-memory, etc.) to be plugged in.

## Install

```
go get github.com/benaskins/axon-auth@latest
```

Requires Go 1.24+.

## Usage

```go
cfg := auth.Config{
    RPID:          "example.com",
    RPOrigins:     []string{"https://example.com"},
    RPDisplayName: "My App",
    CookieDomain:  ".example.com",
}

srv := auth.NewServer(cfg, userStore, sessionStore, passkeyStore, inviteStore)
http.Handle("/", srv)
```

### Key types

- `User`, `Session`, `Invite` — domain types
- `UserStore`, `SessionStore`, `PasskeyStore`, `InviteStore` — persistence interfaces
- `Server` — HTTP handler with registration, login, and session endpoints
- `WebAuthnWrapper` — WebAuthn protocol wrapper
- `Config` — relying party and cookie configuration

### Sub-packages

- `authtest` — in-memory mock stores for testing

## License

Apache 2.0 — see [LICENSE](LICENSE).
