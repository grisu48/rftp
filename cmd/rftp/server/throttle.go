// SPDX-License-Identifier: MIT

package server

import (
	"net"
	"sync"
	"time"
)

// rateLimiter is a token bucket limiting a single connection to a fixed
// rate in bytes per second. The bucket holds at most one second worth of
// tokens (so small bursts are allowed) and is refilled continuously based
// on elapsed time. Tokens may go negative (debt), so time spent waiting is
// accounted against later transfers.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64   // tokens (bytes) per second
	tokens float64   // currently available tokens; may be negative (debt)
	last   time.Time // last refill time
}

// newRateLimiter returns a limiter for the given rate in bytes per second,
// starting with a full bucket.
func newRateLimiter(bytesPerSec int64) *rateLimiter {
	return &rateLimiter{
		rate:   float64(bytesPerSec),
		tokens: float64(bytesPerSec),
		last:   time.Now(),
	}
}

// wait blocks until n bytes worth of tokens have been consumed, sleeping
// for the time the current debt requires at the configured rate.
func (l *rateLimiter) wait(n int) {
	if n <= 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	l.tokens = min(l.rate, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	l.tokens -= float64(n)
	debt := -l.tokens
	l.mu.Unlock()
	if debt > 0 {
		time.Sleep(time.Duration(debt / l.rate * float64(time.Second)))
	}
}

// throttledConn wraps a net.Conn and charges every byte read from or written
// to it against a per-connection rate limiter. Deadlines set on the
// underlying connection keep working unchanged, so a pathologically low
// limit simply surfaces as an I/O timeout (fail-closed).
type throttledConn struct {
	net.Conn
	rl *rateLimiter
}

func (c *throttledConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rl.wait(n)
	return n, err
}

func (c *throttledConn) Write(p []byte) (int, error) {
	c.rl.wait(len(p))
	return c.Conn.Write(p)
}

// throttleConn wraps conn in a throttledConn limited to bytesPerSec bytes
// per second. A limit <= 0 means unlimited and returns conn unchanged.
// Each call creates a fresh limiter, so the limit is per connection and is
// never shared between connections.
func throttleConn(conn net.Conn, bytesPerSec int64) net.Conn {
	if bytesPerSec <= 0 {
		return conn
	}
	return &throttledConn{Conn: conn, rl: newRateLimiter(bytesPerSec)}
}
