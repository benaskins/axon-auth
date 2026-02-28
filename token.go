package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateToken creates a cryptographically random token and returns
// both the plaintext (for cookies) and the SHA-256 hash (for storage).
func GenerateToken() (plaintext, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate token: %w", err)
	}
	plaintext = base64.URLEncoding.EncodeToString(b)
	hash = HashToken(plaintext)
	return plaintext, hash, nil
}

// HashToken returns the SHA-256 hash of a token, base64url-encoded.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(h[:])
}
