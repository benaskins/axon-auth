package auth

import (
	"errors"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrDuplicateUsername = errors.New("username already taken")
	ErrDuplicateEmail    = errors.New("email already registered")
	
	// Password errors
	ErrPasswordTooShort    = errors.New("password must be at least 8 characters")
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoDigit     = errors.New("password must contain at least one digit")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrWeakPassword        = errors.New("password does not meet strength requirements")
	
	// JWT errors
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
	
	// Rate limit errors
	ErrRateLimited = errors.New("too many requests, please try again later")
	
	// RBAC errors
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)
