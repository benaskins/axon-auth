package auth

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	maxReq   int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		maxReq:   maxRequests,
		window:   window,
	}
}

// Allow checks if a request from the given key should be allowed
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-r.window)

	// Get existing requests for this key
	reqs := r.requests[key]

	// Filter out requests outside the window
	var validReqs []time.Time
	for _, t := range reqs {
		if t.After(windowStart) {
			validReqs = append(validReqs, t)
		}
	}

	// Check if we're over the limit
	if len(validReqs) >= r.maxReq {
		r.requests[key] = validReqs
		return false
	}

	// Add this request
	validReqs = append(validReqs, now)
	r.requests[key] = validReqs
	return true
}

// GetRemaining returns the number of remaining requests in the current window
func (r *RateLimiter) GetRemaining(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-r.window)

	reqs := r.requests[key]
	var validReqs []time.Time
	for _, t := range reqs {
		if t.After(windowStart) {
			validReqs = append(validReqs, t)
		}
	}

	return max(0, r.maxReq-len(validReqs))
}

// GetResetTime returns the time when the rate limit window resets
func (r *RateLimiter) GetResetTime(key string) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()

	reqs := r.requests[key]
	if len(reqs) == 0 {
		return time.Now()
	}

	oldest := reqs[0]
	for _, t := range reqs {
		if t.Before(oldest) {
			oldest = t
		}
	}

	return oldest.Add(r.window)
}

// IPKey extracts the client IP from a request for rate limiting
func IPKey(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP if there are multiple
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == ':' {
			return ip[:i]
		}
	}
	return ip
}
