package publicconsole

import (
	"sync"
	"time"
)

// Login rate limiting (ADR-0016). The generated password cannot be guessed,
// but failures still cost: they slow scanners down and keep logs quiet.
const (
	freeFailures   = 5                // consecutive failures allowed per client
	firstLockout   = time.Minute      // lockout after the 5th failure, doubling
	maxLockout     = time.Hour        // cap of the per-client lockout
	globalWindow   = 10 * time.Minute // window of the global failure count
	globalMax      = 50               // failures in the window that pause all logins
	globalLockout  = 10 * time.Minute
	clientIdleTTL  = 2 * time.Hour // forget clients idle this long
	maxTrackedKeys = 10000
)

// Limiter tracks login failures per client and globally.
type Limiter struct {
	mu          sync.Mutex
	now         func() time.Time
	clients     map[string]*clientState
	failures    []time.Time // global failures inside globalWindow
	globalUntil time.Time
}

type clientState struct {
	fails int
	until time.Time
	last  time.Time
}

// NewLimiter returns a Limiter; now may be nil (time.Now).
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, clients: map[string]*clientState{}}
}

// Allow reports whether key may try to log in now, and if not, how long to wait.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.globalUntil) {
		return false, l.globalUntil.Sub(now)
	}
	if st, ok := l.clients[key]; ok && now.Before(st.until) {
		return false, st.until.Sub(now)
	}
	return true, 0
}

// Fail records a failed attempt by key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gc(now)
	st, ok := l.clients[key]
	if !ok {
		st = &clientState{}
		l.clients[key] = st
	}
	st.fails++
	st.last = now
	if st.fails >= freeFailures {
		lock := firstLockout << (st.fails - freeFailures)
		if lock > maxLockout || lock <= 0 {
			lock = maxLockout
		}
		st.until = now.Add(lock)
	}

	cut := now.Add(-globalWindow)
	kept := l.failures[:0]
	for _, t := range l.failures {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	l.failures = append(kept, now)
	if len(l.failures) > globalMax {
		l.globalUntil = now.Add(globalLockout)
		l.failures = l.failures[:0]
	}
}

// Success clears key's failure history.
func (l *Limiter) Success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, key)
}

func (l *Limiter) gc(now time.Time) {
	if len(l.clients) < maxTrackedKeys/2 {
		return
	}
	for k, st := range l.clients {
		if now.Sub(st.last) > clientIdleTTL && now.After(st.until) {
			delete(l.clients, k)
		}
	}
	if len(l.clients) >= maxTrackedKeys {
		// Under a flood keep memory bounded; locked-out clients stay tracked.
		for k, st := range l.clients {
			if now.After(st.until) {
				delete(l.clients, k)
			}
		}
	}
}
