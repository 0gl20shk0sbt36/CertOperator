// Package ratelimit provides a thread-safe in-memory rate limiter.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a thread-safe in-memory rate limiter that tracks attempts per
// address and auto-cleans expired entries.
type Limiter struct {
	mu      sync.Mutex
	entries map[string][]int64 // addr -> list of Unix timestamps (seconds)
}

// New returns a new Limiter.
func New() *Limiter {
	return &Limiter{
		entries: make(map[string][]int64),
	}
}

// Check reports whether the request from addr is allowed.  It records a hit
// and returns false when the number of attempts within the window exceeds max.
//
// Thread-safe.  Old entries outside the window are purged on each check.
func (l *Limiter) Check(addr string, max int, window time.Duration) bool {
	now := time.Now().Unix()
	windowSec := int64(window.Seconds())
	if windowSec < 1 {
		windowSec = 1
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now - windowSec

	// Purge expired entries for this address
	hits := l.entries[addr]
	valid := hits[:0]
	for _, t := range hits {
		if t > cutoff {
			valid = append(valid, t)
		}
	}
	l.entries[addr] = valid

	if len(valid) >= max {
		return false
	}

	l.entries[addr] = append(valid, now)
	return true
}

// Clean removes all entries older than the given window.  Safe to call from a
// background goroutine to prevent unbounded memory growth for addresses that
// never appear again.
func (l *Limiter) Clean(window time.Duration) {
	now := time.Now().Unix()
	cutoff := now - int64(window.Seconds())
	if cutoff < 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for addr, hits := range l.entries {
		valid := hits[:0]
		for _, t := range hits {
			if t > cutoff {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(l.entries, addr)
		} else {
			l.entries[addr] = valid
		}
	}
}
