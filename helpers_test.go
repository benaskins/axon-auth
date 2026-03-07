package auth

import "testing"

func TestIsLocalRedirect(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		isValid bool
	}{
		{"localhost with port", "http://localhost:9876/callback", true},
		{"127.0.0.1 with port", "http://127.0.0.1:9876/callback", true},
		{"localhost no port", "http://localhost/callback", true},
		{"external URL", "https://evil.com/steal", false},
		{"https localhost", "https://localhost:9876/callback", false},
		{"empty", "", false},
		{"javascript", "javascript:alert(1)", false},
		{"data URL", "data:text/html,<h1>hi</h1>", false},
		{"relative path", "/callback", false},
		{"ftp scheme", "ftp://localhost:21/file", false},
		{"non-local host", "http://example.com/callback", false},
		{"localhost with path only", "http://localhost", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isLocalRedirect(tt.url) != tt.isValid {
				t.Errorf("isLocalRedirect(%q) = %v, want %v", tt.url, !tt.isValid, tt.isValid)
			}
		})
	}
}
