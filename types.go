package auth

import "time"

type User struct {
	ID          string
	Username    string
	Email       string
	DisplayName string
	IsAdmin     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Session struct {
	ID         string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time
}

type Invite struct {
	ID          string
	Email       string
	TokenHash   string
	IsBootstrap bool
	Used        bool
	CreatedAt   time.Time
	ExpiresAt   time.Time
}
