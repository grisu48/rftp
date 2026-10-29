package server

import (
	"fmt"
	"net"
	"sync"
)

// PassiveManager allocates passive-mode data listeners from a configured
// port range, rotating round-robin and skipping ports that are in use.
type PassiveManager struct {
	min  int
	max  int
	mu   sync.Mutex
	next int
}

// NewPassiveManager creates a PassiveManager for the inclusive port range
// [min, max]. Invalid ranges are clamped to sane defaults.
func NewPassiveManager(min, max int) *PassiveManager {
	if min < 1 {
		min = 40000
	}
	if max < min {
		max = min
	}
	if max > 65535 {
		max = 65535
	}
	return &PassiveManager{min: min, max: max, next: min}
}

// Listen opens a passive-mode listener bound to ip, trying each port in
// the configured range in turn. It returns an error if no port is available.
func (m *PassiveManager) Listen(ip net.IP) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := m.max - m.min + 1
	for i := 0; i < count; i++ {
		port := m.next
		m.next++
		if m.next > m.max {
			m.next = m.min
		}
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: port})
		if err == nil {
			return ln, nil
		}
	}
	return nil, fmt.Errorf("no available port in passive range %d-%d", m.min, m.max)
}
