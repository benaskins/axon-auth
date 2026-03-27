@AGENTS.md

## Conventions
- One handler file per endpoint group (`handler_register.go`, `handler_login.go`, etc.)
- Session tokens stored as SHA-256 hashes — never store raw tokens
- All hardcoded values go in `Config` struct (`config.go`), not inline
- Use `authtest/` mock stores for all tests — no database dependency in this package
- Handler pattern follows axon conventions: `func(w, r)` with axon HTTP helpers

## Constraints
- Security-critical code — timing attack hardening in token comparison is intentional, do not simplify
- Do not simplify or refactor crypto/token code without explicit approval
- No dependencies beyond axon and go-webauthn — no database/sql, no drivers
- Session tokens only — no JWTs
- Never import other axon-* service packages (axon-chat, axon-gate, etc.)

## Testing
- `go test ./...` — all tests use in-memory mock stores, no database needed
- `go vet ./...` — lint
- When adding endpoints, add corresponding tests using `authtest/` stores
