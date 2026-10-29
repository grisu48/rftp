// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"net"
	"sync"

	"github.com/grisu48/rftp/cmd/rftp/config"
	"github.com/grisu48/rftp/cmd/rftp/logger"
)

// Server is the FTP server: it owns the control listener, the passive
// port manager and the set of active sessions.
type Server struct {
	cfg  *config.Config
	ln   net.Listener
	pasv *PassiveManager

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
	return &Server{
		cfg:      cfg,
		ln:       ln,
		pasv:     NewPassiveManager(cfg.PassivePortMin, cfg.PassivePortMax),
		sessions: make(map[*Session]struct{}),
	}, nil
}

// Addr returns the address the control listener is bound to.
func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

// Serve runs the accept loop until the listener is closed (via Close) or a
// fatal accept error occurs.
func (s *Server) Serve() error {
	logger.Info("FTP server listening addr=%s serve_dir=%s", s.ln.Addr().String(), s.cfg.ServeDir)
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
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

	s.ln.Close()
	for _, sess := range sessions {
		sess.Close()
	}
	s.wg.Wait()
	logger.Info("server stopped")
}
