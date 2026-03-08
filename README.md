# axon-auth

> Domain package · Part of the [lamina](https://github.com/benaskins/lamina-mono) workspace

WebAuthn-based authentication with passkey registration, login, session management, and invite-based user onboarding. Defines store interfaces (`UserStore`, `SessionStore`, `PasskeyStore`, `InviteStore`) so any persistence backend can be plugged in. HTTP handlers are composed into a `Server` that mounts onto your existing mux.

## Getting started

```
go get github.com/benaskins/axon-auth@latest
```

axon-auth is a domain package — it provides types, interfaces, and HTTP handlers but no `main` function. You assemble it in your own composition root by supplying store implementations and configuration. See [`example/main.go`](example/main.go) for a minimal wiring example.

## Key types

- **`Config`** — relying party ID, origins, cookie domain, session/invite durations
- **`Server`** — HTTP handler with registration, login, validation, and logout endpoints
- **`User`**, **`Session`**, **`Invite`** — domain types
- **`UserStore`**, **`SessionStore`**, **`PasskeyStore`**, **`InviteStore`** — persistence interfaces
- **`WebAuthnWrapper`** — WebAuthn protocol wrapper around go-webauthn
- **`authtest`** — in-memory mock stores for testing

## License

MIT
