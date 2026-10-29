package server

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"anonftp/ftp"
	"anonftp/logger"
)

const (
	// idleTimeout is how long a control connection may sit without a command.
	idleTimeout = 5 * time.Minute
	// maxLineLen caps the length of a single command line.
	maxLineLen = 8192
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

// Session holds the state of one FTP control connection.
type Session struct {
	srv  *Server
	conn net.Conn
	r    *bufio.Reader

	remoteAddr string

	user     string // pending/accepted anonymous user name
	loggedIn bool
	cwd      string // virtual working directory, always absolute
	typ      ftp.TransferType

	mu         sync.Mutex // guards pasvLn and writes to conn
	activeAddr *net.TCPAddr
	pasvLn     net.Listener

	quit bool
}

// NewSession creates a session for a freshly accepted control connection.
func NewSession(srv *Server, conn net.Conn) *Session {
	return &Session{
		srv:        srv,
		conn:       conn,
		r:          bufio.NewReader(conn),
		remoteAddr: conn.RemoteAddr().String(),
		cwd:        "/",
		typ:        ftp.TypeASCII,
	}
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
		s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		line, err := s.readLine()
		if err != nil {
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
	s.conn.Close()
	if s.pasvLn != nil {
		s.pasvLn.Close()
		s.pasvLn = nil
	}
}

// readLine reads one CRLF-terminated command line.
func (s *Session) readLine() (string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLineLen {
		return "", fmt.Errorf("command line too long (%d bytes)", len(line))
	}
	return line, nil
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
	s.conn.SetWriteDeadline(time.Now().Add(time.Minute))
	fmt.Fprintf(s.conn, "%s\r\n", line)
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

// openDataConn establishes the data connection for a transfer: it accepts a
// passive connection if PASV/EPSV was used, dials out if PORT/EPRT was used,
// or fails with errNoDataConn.
func (s *Session) openDataConn() (net.Conn, error) {
	if s.pasvLn != nil {
		ln := s.pasvLn
		if tl, ok := ln.(*net.TCPListener); ok {
			tl.SetDeadline(time.Now().Add(dataConnectTimeout))
		}
		conn, err := ln.Accept()
		s.closePassive()
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(dataTransferTimeout))
		return conn, nil
	}
	if s.activeAddr != nil {
		d := net.Dialer{Timeout: dataConnectTimeout}
		conn, err := d.Dial("tcp", s.activeAddr.String())
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(dataTransferTimeout))
		return conn, nil
	}
	return nil, errNoDataConn
}

// closePassive closes the passive listener, if any.
func (s *Session) closePassive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pasvLn != nil {
		s.pasvLn.Close()
		s.pasvLn = nil
	}
}

// setPassive replaces the passive listener, closing any previous one.
func (s *Session) setPassive(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pasvLn != nil {
		s.pasvLn.Close()
	}
	s.pasvLn = ln
}

// setActive records an active-mode (PORT/EPRT) data address and cancels
// any passive listener, as required by RFC 959.
func (s *Session) setActive(addr *net.TCPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pasvLn != nil {
		s.pasvLn.Close()
		s.pasvLn = nil
	}
	s.activeAddr = addr
}
