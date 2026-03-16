# axon-auth

> Domain package · Part of the [lamina](https://github.com/benaskins/lamina-mono) workspace

WebAuthn-based authentication with passkey registration, login, session management, and invite-based user onboarding. Defines store interfaces (`UserStore`, `SessionStore`, `PasskeyStore`, `InviteStore`) so any persistence backend can be plugged in. HTTP handlers are composed into a `Server` that mounts onto your existing mux.

## Getting started

```
go get github.com/benaskins/axon-auth@latest
```

axon-auth is a domain package — it provides types, interfaces, and HTTP handlers but no `main` function. You assemble it in your own composition root by supplying store implementations and configuration. See [`example/main.go`](example/main.go) for a minimal wiring example.

```go
cfg := auth.Config{
    RPID:            "example.com",
    RPDisplayName:   "Example App",
    RPOrigins:       []string{"https://example.com"},
    CookieDomain:    ".example.com",
    SecureCookie:    true,
    SessionDuration: 24 * time.Hour,
    InviteDuration:  7 * 24 * time.Hour,
}

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

## Key types

- **`Config`** — relying party ID, origins, cookie domain, session/invite durations
- **`Server`** — HTTP handler with registration, login, validation, and logout endpoints
- **`User`**, **`Session`**, **`Invite`** — domain types
- **`UserStore`**, **`SessionStore`**, **`PasskeyStore`**, **`InviteStore`** — persistence interfaces
- **`WebAuthnWrapper`** — WebAuthn protocol wrapper around go-webauthn
- **`authtest`** — in-memory mock stores for testing

## License

MIT
