// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestRateLimiterWait verifies that the token bucket lets a full bucket pass
// immediately and then blocks for the time the debt requires.
func TestRateLimiterWait(t *testing.T) {
	const rate = 10 * 1000 * 1000 // 10 MB/s
	rl := newRateLimiter(rate)

	// The bucket starts full with one second worth of tokens: this wait
	// must return (almost) immediately.
	start := time.Now()
	rl.wait(rate)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("wait for a full bucket took %v, want immediate", elapsed)
	}

	// The bucket is now empty; consuming another 10% of a second worth of
	// tokens must block for about 100ms.
	start = time.Now()
	rl.wait(rate / 10)
	elapsed := time.Since(start)
	if elapsed < 90*time.Millisecond {
		t.Errorf("wait past the bucket took %v, want at least ~100ms", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Errorf("wait past the bucket took %v, unreasonably long", elapsed)
	}
}

// TestThrottledConn verifies that a wrapped connection moves the data intact
// but no faster than the configured rate (minus the initial burst).
func TestThrottledConn(t *testing.T) {
	const rate = 10 << 20  // 10 MiB/s
	const total = 11 << 20 // 11 MiB: 10 MiB burst + 1 MiB throttled

	server, client := net.Pipe()
	defer client.Close()

	received := make(chan int, 1)
	go func() {
		n, err := io.Copy(io.Discard, client)
		if err != nil {
			t.Errorf("read from pipe: %v", err)
		}
		received <- int(n)
	}()

	tc := throttleConn(server, rate)
	data := bytes.Repeat([]byte("x"), 32<<10)
	start := time.Now()
	for written := 0; written < total; written += len(data) {
		n, err := tc.Write(data)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if n != len(data) {
			t.Fatalf("short write: %d", n)
		}
	}
	_ = tc.Close()
	elapsed := time.Since(start)

	if n := <-received; n != total {
		t.Errorf("received %d bytes, want %d", n, total)
	}
	// (total - rate) bytes beyond the initial full bucket at `rate` B/s
	// must take at least (total-rate)/rate = 100ms.
	if elapsed < 90*time.Millisecond {
		t.Errorf("writing %d bytes at %d B/s took %v, want at least ~100ms", total, rate, elapsed)
	}
}

// TestThrottleConnUnlimited verifies that a non-positive limit leaves the
// connection untouched.
func TestThrottleConnUnlimited(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if got := throttleConn(c1, 0); got != c1 {
		t.Error("throttleConn(conn, 0) must return the connection unchanged")
	}
	if got := throttleConn(c1, -1); got != c1 {
		t.Error("throttleConn(conn, -1) must return the connection unchanged")
	}
	if _, ok := throttleConn(c1, 1000).(*throttledConn); !ok {
		t.Error("throttleConn(conn, 1000) must wrap the connection")
	}
}
