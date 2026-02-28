package auth

import (
	"encoding/base64"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	plaintext, hash, err := GenerateToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if len(plaintext) == 0 {
		t.Error("plaintext is empty")
	}
	if len(hash) == 0 {
		t.Error("hash is empty")
	}

	// Verify plaintext is base64url encoded
	_, err = base64.URLEncoding.DecodeString(plaintext)
	if err != nil {
		t.Errorf("plaintext is not valid base64url: %v", err)
	}

	// Verify hash matches
	if HashToken(plaintext) != hash {
		t.Error("hash does not match HashToken(plaintext)")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	token := "test-token-value"
	h1 := HashToken(token)
	h2 := HashToken(token)
	if h1 != h2 {
		t.Error("HashToken is not deterministic")
	}
}
