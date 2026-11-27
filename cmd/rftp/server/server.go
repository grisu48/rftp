// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/grisu48/rftp/cmd/rftp/config"
	"github.com/grisu48/rftp/cmd/rftp/ftp"
	"github.com/grisu48/rftp/cmd/rftp/logger"
)

// Server is the FTP server: it owns the control listener, the passive
// port manager and the set of active sessions.
type Server struct {
	cfg  *config.Config
	ln   net.Listener
	pasv *PassiveManager

	// connSlots is the global limit of parallel control connections: a
	// buffered channel with one slot per allowed connection. It is nil when
	// no limit is configured (max_connections: 0, unlimited). Only control
	// connections acquire a slot; data connections never do.
	connSlots chan struct{}

	mu       sync.Mutex
	sessions map[*Session]struct{}
	closed   bool

	wg sync.WaitGroup
}

// New creates a Server and binds the control listener. The accept loop is
// started with Serve.
func New(cfg *config.Config) (*Server, error) {
	ln, err := NewListener(cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	var connSlots chan struct{}
	if cfg.MaxConnections > 0 {
		connSlots = make(chan struct{}, cfg.MaxConnections)
	}
	return &Server{
		cfg:       cfg,
		ln:        ln,
		pasv:      NewPassiveManager(cfg.PassivePortMin, cfg.PassivePortMax),
		connSlots: connSlots,
		sessions:  make(map[*Session]struct{}),
	}, nil
}

// Addr returns the address the control listener is bound to.
func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

// Serve runs the accept loop until the listener is closed (via Close) or a
// fatal accept error occurs.
func (s *Server) Serve() error {
	logger.Info("FTP server listening addr=%s serve_dir=%s max_connections=%d", s.ln.Addr().String(), s.cfg.ServeDir, s.cfg.MaxConnections)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.isClosed() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		// Enforce the global control-connection limit (max_connections).
		// Only control connections are counted here; data connections
		// (passive accepts and active dials in Session.openDataConn) never
		// pass through this loop and never consume a slot.
		if !s.acquireConnSlot() {
			logger.Warn("connection rejected: too many connections remote=%s", conn.RemoteAddr())
			fmt.Fprintf(conn, "%d Too many connections, closing control connection\r\n", ftp.R421ServiceUnavailable)
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.releaseConnSlot()
			s.handleConn(conn)
		}()
	}
}

// acquireConnSlot reserves one slot of the global control-connection limit.
// It returns false immediately when the limit is reached; it never blocks,
// so an over-limit connection is rejected instead of queueing.
func (s *Server) acquireConnSlot() bool {
	if s.connSlots == nil {
		return true // no limit configured
	}
	select {
	case s.connSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseConnSlot frees the slot taken by a control connection when its
// session ends.
func (s *Server) releaseConnSlot() {
	if s.connSlots != nil {
		<-s.connSlots
	}
}

func (s *Server) handleConn(conn net.Conn) {
	sess := NewSession(s, conn)
	s.addSession(sess)
	defer s.removeSession(sess)
	sess.Run()
}

func (s *Server) addSession(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess] = struct{}{}
}

func (s *Server) removeSession(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sess)
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close stops accepting new connections, closes all active sessions and
// waits for them to finish. It is safe to call multiple times.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	sessions := make([]*Session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	if err := s.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Warn("cannot close listener: %v", err)
	}
	for _, sess := range sessions {
		sess.Close()
	}
	s.wg.Wait()
	logger.Info("server stopped")
}
