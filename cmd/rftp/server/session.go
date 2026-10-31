// SPDX-License-Identifier: MIT

package server

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/grisu48/rftp/cmd/rftp/ftp"
	"github.com/grisu48/rftp/cmd/rftp/logger"
)

const (
	// idleTimeout is how long a control connection may sit without a command.
	idleTimeout = 5 * time.Minute
	// maxLineLen caps the length of a single command line (including CRLF).
	// The read buffer is sized to maxLineLen, so an overlong line is detected
	// before it can be buffered in full (DoS protection).
	maxLineLen = 8192
	// maxLineDrain is the hard cap up to which the remainder of an overlong
	// command line is discarded; beyond it the connection is closed.
	maxLineDrain = 1 << 20
	// dataConnectTimeout bounds establishing an active data connection and
	// accepting a passive one.
	dataConnectTimeout = 30 * time.Second
	// dataTransferTimeout bounds a single data transfer.
	dataTransferTimeout = 30 * time.Minute
)

// errAccessDenied is returned when a path attempts to escape the served root.
var errAccessDenied = errors.New("access denied")

// errNoDataConn is returned when a transfer is requested before PORT/PASV.
var errNoDataConn = errors.New("no data connection")

// errLineTooLong is returned when a command line exceeds maxLineLen. The
// remainder of the line has already been drained, so the session stays usable.
var errLineTooLong = errors.New("command line too long")

// Session holds the state of one FTP control connection.
type Session struct {
	srv  *Server
	conn net.Conn
	r    *bufio.Reader

	remoteAddr string
	remoteIP   net.IP // normalized IP of the control connection peer

	user     string // pending/accepted anonymous user name
	loggedIn bool
	cwd      string // virtual working directory, always absolute
	typ      ftp.TransferType

	mu         sync.Mutex // guards pasvLn, activeAddr and writes to conn
	activeAddr *net.TCPAddr
	pasvLn     net.Listener

	quit bool
}

// NewSession creates a session for a freshly accepted control connection.
func NewSession(srv *Server, conn net.Conn) *Session {
	remoteIP := net.IP(nil)
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		remoteIP = normalizeIP(net.ParseIP(host))
	}
	return &Session{
		srv:        srv,
		conn:       conn,
		r:          bufio.NewReaderSize(conn, maxLineLen),
		remoteAddr: conn.RemoteAddr().String(),
		remoteIP:   remoteIP,
		cwd:        "/",
		typ:        ftp.TypeASCII,
	}
}

// normalizeIP maps IPv4-mapped IPv6 addresses to their IPv4 form so that
// peers can be compared reliably across address families.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// sameIP reports whether two IPs are equal after normalization.
func sameIP(a, b net.IP) bool {
	return normalizeIP(a).Equal(normalizeIP(b))
}

// checkDataAddr enforces the anti-FTP-bounce rule (CWE-441): the data
// connection address supplied via PORT/EPRT/LPRT must belong to the same
// host as the control connection. Otherwise the server could be abused to
// open connections to arbitrary third-party hosts and ports (port scanning,
// attacks on internal services).
func (s *Session) checkDataAddr(ip net.IP) bool {
	return s.remoteIP != nil && sameIP(ip, s.remoteIP)
}

// Run handles the control connection until the client quits, the idle
// timeout expires or the connection is closed (e.g. by Server.Close).
func (s *Session) Run() {
	defer s.conn.Close()
	defer s.closePassive()
	logger.Info("connection opened remote=%s", s.remoteAddr)
	defer logger.Info("connection closed remote=%s", s.remoteAddr)

	s.reply(ftp.R220ServiceReady, "Anonymous FTP server ready")

	for !s.quit {
		_ = s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		line, err := s.readLine()
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				// The line was overlong but has been drained; keep the session.
				logger.Warn("overlong command line remote=%s", s.remoteAddr)
				s.reply(ftp.R500SyntaxError, "Command line too long")
				continue
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				s.reply(ftp.R421ServiceUnavailable, "Idle timeout, closing control connection")
			}
			return
		}
		cmd := ftp.ParseCommand(line)
		if cmd.Name == "" {
			s.reply(ftp.R500SyntaxError, "Command not recognized")
			continue
		}
		if cmd.Name != ftp.CmdPASS {
			logger.Debug("command remote=%s cmd=%s arg=%s", s.remoteAddr, cmd.Name, cmd.Arg)
		} else {
			logger.Debug("command remote=%s cmd=%s", s.remoteAddr, cmd.Name)
		}
		s.handleCommand(cmd)
	}
}

// Close terminates the session. It is called by Server.Close on shutdown.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.Close()
	if s.pasvLn != nil {
		_ = s.pasvLn.Close()
		s.pasvLn = nil
	}
}

// readLine reads one CRLF-terminated command line. The read buffer is capped
// at maxLineLen, so a line longer than that is detected via
// bufio.ErrBufferFull before it is fully buffered in memory; the remainder
// of the line is then drained (bounded by maxLineDrain) and errLineTooLong
// is returned, keeping the connection in sync.
func (s *Session) readLine() (string, error) {
	line, err := s.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		if derr := s.discardRestOfLine(); derr != nil {
			return "", derr
		}
		return "", errLineTooLong
	}
	if err != nil {
		return "", err
	}
	if len(line) > maxLineLen {
		return "", errLineTooLong
	}
	return string(line), nil
}

// discardRestOfLine reads and discards input up to and including the next
// newline, bounded by maxLineDrain bytes.
func (s *Session) discardRestOfLine() error {
	drained := 0
	for {
		frag, err := s.r.ReadSlice('\n')
		drained += len(frag)
		if err == nil {
			return nil // reached the end of the overlong line
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			if drained > maxLineDrain {
				return fmt.Errorf("command line exceeds %d bytes, closing connection", maxLineDrain)
			}
			continue
		}
		return err // EOF or connection error
	}
}

// reply writes a single-line reply: "<code> <message>\r\n".
func (s *Session) reply(code int, format string, args ...any) {
	s.writeLine(fmt.Sprintf("%d %s", code, fmt.Sprintf(format, args...)))
}

// replyLines writes a multi-line reply: "<code>-<line>" for all but the
// last line and "<code> <line>" for the last one (RFC 959 section 4.2).
func (s *Session) replyLines(code int, lines []string) {
	for i, line := range lines {
		if i == len(lines)-1 {
			s.writeLine(fmt.Sprintf("%d %s", code, line))
		} else {
			s.writeLine(fmt.Sprintf("%d-%s", code, line))
		}
	}
}

func (s *Session) writeLine(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(time.Minute))
	if _, err := fmt.Fprintf(s.conn, "%s\r\n", line); err != nil {
		logger.Debug("cannot write reply remote=%s error=%v", s.remoteAddr, err)
	}
}

// resolvePath maps a client-supplied path (relative to cwd or absolute)
// onto a virtual absolute path inside the served root. Any attempt to
// traverse above the root (e.g. "../../etc") is rejected with errAccessDenied.
func resolvePath(cwd, arg string) (string, error) {
	if arg == "" {
		return cwd, nil
	}
	var raw string
	if strings.HasPrefix(arg, "/") {
		raw = arg
	} else {
		raw = cwd + "/" + arg
	}
	depth := 0
	for _, part := range strings.Split(raw, "/") {
		switch part {
		case "", ".":
			// no-op
		case "..":
			depth--
			if depth < 0 {
				return "", errAccessDenied
			}
		default:
			depth++
		}
	}
	return path.Clean(raw), nil
}

// realPath maps a virtual path onto a real filesystem path and verifies,
// after resolving symlinks, that the result stays inside the served root.
// Symlinks pointing outside the root are rejected with errAccessDenied.
//
// It implements the symlink policy and produces the access-denied error, but
// the actual file access must go through fsRoot (os.Root), which enforces the
// same policy atomically and therefore closes the check-then-open TOCTOU
// window of this function.
func (s *Session) realPath(virtual string) (string, error) {
	root := s.srv.cfg.ServeDir
	real := filepath.Join(root, virtual)
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	prefix := rootResolved
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if resolved != rootResolved && !strings.HasPrefix(resolved, prefix) {
		return "", errAccessDenied
	}
	return resolved, nil
}

// scoped resolves virtual via realPath (which enforces the symlink policy
// and returns errAccessDenied for escapes) and returns an os.Root scoped to
// the symlink-resolved serve directory together with the resolved path
// relative to it. Accessing name through the returned root is confined to
// the served root by the kernel (openat2 RESOLVE_BENEATH, or Go's fallback),
// so a symlink swapped in between the policy check and the open cannot make
// the access escape the root (no TOCTOU window).
func (s *Session) scoped(virtual string) (root *os.Root, name string, real string, err error) {
	real, err = s.realPath(virtual)
	if err != nil {
		return nil, "", "", err
	}
	rootResolved, err := filepath.EvalSymlinks(s.srv.cfg.ServeDir)
	if err != nil {
		return nil, "", "", err
	}
	rel, err := filepath.Rel(rootResolved, real)
	if err != nil {
		return nil, "", "", err
	}
	root, err = os.OpenRoot(rootResolved)
	if err != nil {
		return nil, "", "", err
	}
	return root, rel, real, nil
}

// openDataConn establishes the data connection for a transfer: it accepts a
// passive connection if PASV/EPSV was used, dials out if PORT/EPRT was used,
// or fails with errNoDataConn.
//
// In passive mode only a connection from the same peer as the control
// connection is accepted; a connection from any other host is closed and
// the accept loop continues until the deadline, so the passive port cannot
// be hijacked by a third party.
func (s *Session) openDataConn() (net.Conn, error) {
	// Grab and clear the passive listener / active address under the lock:
	// Close may run concurrently from another goroutine (server shutdown).
	s.mu.Lock()
	ln := s.pasvLn
	s.pasvLn = nil
	active := s.activeAddr
	s.mu.Unlock()

	if ln != nil {
		defer ln.Close()
		if tl, ok := ln.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(dataConnectTimeout))
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				return nil, err
			}
			if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok && !sameIP(ra.IP, s.remoteIP) {
				logger.Warn("rejected passive data connection from wrong peer remote=%s", conn.RemoteAddr())
				_ = conn.Close()
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(dataTransferTimeout))
			return conn, nil
		}
	}
	if active != nil {
		d := net.Dialer{Timeout: dataConnectTimeout}
		conn, err := d.Dial("tcp", active.String())
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(time.Now().Add(dataTransferTimeout))
		return conn, nil
	}
	return nil, errNoDataConn
}

// closePassive closes the passive listener, if any.
func (s *Session) closePassive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pasvLn != nil {
		_ = s.pasvLn.Close()
		s.pasvLn = nil
	}
}

// setPassive replaces the passive listener, closing any previous one.
func (s *Session) setPassive(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pasvLn != nil {
		_ = s.pasvLn.Close()
	}
	s.pasvLn = ln
}

// setActive records an active-mode (PORT/EPRT) data address and cancels
// any passive listener, as required by RFC 959.
func (s *Session) setActive(addr *net.TCPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pasvLn != nil {
		_ = s.pasvLn.Close()
		s.pasvLn = nil
	}
	s.activeAddr = addr
}
