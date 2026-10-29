package server

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestPassiveManagerListensInRange(t *testing.T) {
	// Find a free base port to build a small range from.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	m := NewPassiveManager(base, base+4)

	ln1, err := m.Listen(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln1.Close()
	p1 := ln1.Addr().(*net.TCPAddr).Port
	if p1 < base || p1 > base+4 {
		t.Errorf("port %d outside range %d-%d", p1, base, base+4)
	}

	// Second listener gets a different port from the range.
	ln2, err := m.Listen(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln2.Close()
	p2 := ln2.Addr().(*net.TCPAddr).Port
	if p2 == p1 {
		t.Errorf("expected different ports, both got %d", p1)
	}
}

func TestPassiveManagerExhaustsRange(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	m := NewPassiveManager(base, base) // single-port range
	ln, err := m.Listen(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// The only port in the range is taken now.
	if _, err := m.Listen(net.ParseIP("127.0.0.1")); err == nil {
		t.Error("expected error when the passive port range is exhausted")
	}

	// After closing, the port can be acquired again.
	ln.Close()
	ln2, err := m.Listen(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("Listen after close: %v", err)
	}
	ln2.Close()
}

func TestPassiveManagerSkipsBusyPorts(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	m := NewPassiveManager(base, base+3)

	// Occupy the first two ports of the range.
	busy1, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(base)))
	if err != nil {
		t.Fatal(err)
	}
	defer busy1.Close()
	busy2, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(base+1)))
	if err != nil {
		t.Fatal(err)
	}
	defer busy2.Close()

	// The manager must skip the busy ports and use a free one.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ln, err := m.Listen(net.ParseIP("127.0.0.1"))
		if err == nil {
			p := ln.Addr().(*net.TCPAddr).Port
			if p != base && p != base+1 {
				ln.Close()
				break
			}
			ln.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("manager did not find a free port in the range")
		}
	}
}
