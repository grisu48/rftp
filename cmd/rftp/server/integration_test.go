// SPDX-License-Identifier: MIT

package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grisu48/rftp/cmd/rftp/config"
)

// --- Authentication (spec: anonymous-only) -----------------------------------

func TestAnonymousLoginAccepted(t *testing.T) {
	_, addr := startTestServer(t, nil)

	for _, user := range []string{"anonymous", "ftp", "Anonymous", "FTP"} {
		c := dialTestClient(t, addr)
		c.cmd("USER %s", user)
		c.expect(331, "Anonymous login ok, send your complete email address as your password")
		c.cmd("PASS anything@example.com")
		c.expect(230, "Anonymous access granted")
		c.conn.Close()
	}
}

func TestNonAnonymousLoginRejected(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)

	c.cmd("USER root")
	c.expect(530, "Anonymous access only")

	// The server must close the connection after rejecting the user.
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Fatal("expected connection to be closed after non-anonymous USER")
	}
}

func TestPassBeforeUser(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.cmd("PASS whatever")
	c.expect(503, "Login with USER first")
}

func TestCommandsRequireLogin(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	for _, cmd := range []string{"PWD", "CWD /", "LIST", "RETR hello.txt", "SIZE hello.txt", "PASV"} {
		c.cmd("%s", cmd)
		c.expect(530, "Please login with USER and PASS")
	}
}

// --- Read-only enforcement (spec: write commands rejected) --------------------

func TestWriteCommandsRejected(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	writeCmds := []string{
		"STOR newfile.txt", "APPE hello.txt", "STOU", "DELE hello.txt",
		"RNFR hello.txt", "RNTO other.txt", "MKD newdir", "RMD pub",
		"XMKD newdir", "XRMD pub", "SITE CHMOD 777 hello.txt",
	}
	for _, cmd := range writeCmds {
		c.cmd("%s", cmd)
		c.expect(550, "Read-only file system")
	}

	// The session is still usable after the rejected commands.
	c.cmd("NOOP")
	c.expect(200)
}

func TestWriteCommandDoesNotModifyFilesystem(t *testing.T) {
	srv, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("STOR evil.txt")
	c.expect(550)
	c.cmd("MKD evil-dir")
	c.expect(550)
	c.cmd("DELE hello.txt")
	c.expect(550)

	if _, err := os.Stat(filepath.Join(srv.cfg.ServeDir, "evil.txt")); !os.IsNotExist(err) {
		t.Error("STOR created a file despite being rejected")
	}
	if _, err := os.Stat(filepath.Join(srv.cfg.ServeDir, "evil-dir")); !os.IsNotExist(err) {
		t.Error("MKD created a directory despite being rejected")
	}
	if _, err := os.Stat(filepath.Join(srv.cfg.ServeDir, "hello.txt")); err != nil {
		t.Error("DELE removed a file despite being rejected")
	}
}

// --- TLS rejection (spec: plain FTP only) -------------------------------------

func TestTLSCommandsRejected(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("AUTH TLS")
	c.expect(502, "TLS not supported")
	c.cmd("AUTH SSL")
	c.expect(502, "TLS not supported")
	c.cmd("PROT P")
	c.expect(502, "TLS not supported")
}

// --- Basic protocol ------------------------------------------------------------

func TestUnknownCommand(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()
	c.cmd("FOOBAR")
	c.expect(500, "Command not recognized")
}

func TestNoopAndQuit(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("NOOP")
	c.expect(200, "NOOP ok")

	c.cmd("QUIT")
	c.expect(221, "Goodbye")

	// Connection is closed after QUIT.
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Fatal("expected connection to be closed after QUIT")
	}
}

func TestSystFeatHelp(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("SYST")
	c.expect(215, "UNIX Type: L8")

	c.cmd("FEAT")
	lines := c.expect(211)
	joined := strings.Join(lines, "\n")
	for _, feat := range []string{"UTF8", "SIZE", "MDTM"} {
		if !strings.Contains(joined, feat) {
			t.Errorf("FEAT reply missing %q: %v", feat, lines)
		}
	}
	// Multi-line replies use "211-" continuation and end with "211 ".
	if !strings.HasPrefix(lines[0], "211-") {
		t.Errorf("FEAT first line should be a continuation, got %q", lines[0])
	}
	if !strings.HasPrefix(lines[len(lines)-1], "211 ") {
		t.Errorf("FEAT last line should terminate the reply, got %q", lines[len(lines)-1])
	}

	c.cmd("HELP")
	c.expect(214, "USER", "RETR")
}

func TestTypeModeStru(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("TYPE A")
	c.expect(200, "Type set to ASCII")
	c.cmd("TYPE I")
	c.expect(200, "Type set to Image")
	c.cmd("TYPE A N")
	c.expect(200)
	c.cmd("TYPE X")
	c.expect(504)

	c.cmd("MODE S")
	c.expect(200)
	c.cmd("MODE B")
	c.expect(504)

	c.cmd("STRU F")
	c.expect(200)
	c.cmd("STRU R")
	c.expect(504)
}

func TestOptsUTF8(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("OPTS UTF8 ON")
	c.expect(200, "UTF8")
	c.cmd("OPTS UTF8 OFF")
	c.expect(200)
	c.cmd("OPTS FOO BAR")
	c.expect(501)
}

// --- Navigation -----------------------------------------------------------------

func TestPwdCwdCdup(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("PWD")
	c.expect(257, `"/" is the current directory`)

	c.cmd("CWD pub")
	c.expect(250)
	c.cmd("PWD")
	c.expect(257, `"/pub" is the current directory`)

	c.cmd("CDUP")
	c.expect(250)
	c.cmd("PWD")
	c.expect(257, `"/" is the current directory`)

	// CDUP at the root stays at the root.
	c.cmd("CDUP")
	c.expect(250)
	c.cmd("PWD")
	c.expect(257, `"/" is the current directory`)

	// CWD to a nonexistent directory fails.
	c.cmd("CWD no-such-dir")
	c.expect(550)

	// CWD to a regular file fails.
	c.cmd("CWD hello.txt")
	c.expect(550, "Not a directory")
}

func TestPathTraversalBlocked(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	traversals := []string{
		"CWD ../../etc",
		"CWD /../../etc",
		"CWD ..",
		"RETR ../../etc/passwd",
		"RETR /../../etc/passwd",
		"RETR ../../../etc/passwd",
		"SIZE ../../etc/passwd",
		"MDTM /../etc/passwd",
		"LIST ../../",
		"NLST /..",
	}
	for _, cmd := range traversals {
		c.cmd("%s", cmd)
		c.expect(550, "Access denied")
	}

	// The working directory must be unchanged after the attempts.
	c.cmd("PWD")
	c.expect(257, `"/" is the current directory`)
}

func TestSymlinkEscapeBlocked(t *testing.T) {
	srv, addr := startTestServer(t, nil)

	// A secret file outside the served root.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Symlink inside the root pointing outside (absolute and relative).
	if err := os.Symlink(secret, filepath.Join(srv.cfg.ServeDir, "escape-abs.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", filepath.Base(outside), "secret.txt"),
		filepath.Join(srv.cfg.ServeDir, "escape-rel.txt")); err != nil {
		t.Fatal(err)
	}
	// Symlink inside the root pointing to another file inside the root (allowed).
	if err := os.Symlink(filepath.Join(srv.cfg.ServeDir, "hello.txt"),
		filepath.Join(srv.cfg.ServeDir, "ok-link.txt")); err != nil {
		t.Fatal(err)
	}

	c := dialTestClient(t, addr)
	c.login()

	// Absolute symlink escape.
	setupActiveMode(t, c)
	c.cmd("RETR escape-abs.txt")
	c.expect(550, "Access denied")

	// Relative symlink escape.
	setupActiveMode(t, c)
	c.cmd("RETR escape-rel.txt")
	c.expect(550, "Access denied")

	// Symlink staying inside the root works.
	ln := setupActiveMode(t, c)
	c.cmd("RETR ok-link.txt")
	c.expect(150)
	if got := readDataConn(t, c, ln); got != "hello world\n" {
		t.Errorf("RETR via internal symlink data = %q", got)
	}
	c.expect(226)
}

// --- SIZE / MDTM -----------------------------------------------------------------

func TestSizeAndMdtm(t *testing.T) {
	srv, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	// hello.txt contains "hello world\n" = 12 bytes.
	c.cmd("SIZE hello.txt")
	c.expect(213, "12")

	// Absolute path works too.
	c.cmd("SIZE /pub/data.bin")
	c.expect(213, "4")

	// Directories are not sized.
	c.cmd("SIZE pub")
	c.expect(550, "Not a regular file")

	// Missing files.
	c.cmd("SIZE missing.txt")
	c.expect(550)

	// MDTM returns the modification time of the served file.
	info, err := os.Stat(filepath.Join(srv.cfg.ServeDir, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := info.ModTime().UTC().Format("20060102150405")
	c.cmd("MDTM hello.txt")
	c.expect(213, want)

	c.cmd("MDTM missing.txt")
	c.expect(550)
}

// --- Retrieval (active mode) ------------------------------------------------------

// setupActiveMode points the client at a fresh data listener via PORT.
func setupActiveMode(t *testing.T, c *testClient) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	c.cmd("PORT 127,0,0,1,%d,%d", port>>8, port&0xff)
	c.expect(200, "PORT command successful")
	return ln
}

// readDataConn accepts one data connection from ln and returns its contents.
func readDataConn(t *testing.T, c *testClient, ln net.Listener) string {
	t.Helper()
	dc, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept data connection: %v", err)
	}
	defer dc.Close()
	return readDataAll(t, dc)
}

func TestRetrActiveMode(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln := setupActiveMode(t, c)
	c.cmd("RETR hello.txt")
	c.expect(150, "Opening BINARY mode data connection")
	if got := readDataConn(t, c, ln); got != "hello world\n" {
		t.Errorf("RETR data = %q, want %q", got, "hello world\n")
	}
	c.expect(226, "Transfer complete")
}

func TestRetrBinaryFile(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln := setupActiveMode(t, c)
	c.cmd("RETR /pub/data.bin")
	c.expect(150)
	if got := readDataConn(t, c, ln); got != "\x00\x01\x02\x03" {
		t.Errorf("RETR data = %q, want binary bytes", got)
	}
	c.expect(226)
}

func TestRetrNotFound(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln := setupActiveMode(t, c)
	c.cmd("RETR missing.txt")
	c.expect(550, "No such file or directory")
	ln.Close()
}

func TestRetrDirectoryRejected(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln := setupActiveMode(t, c)
	c.cmd("RETR pub")
	c.expect(550, "Not a regular file")
	ln.Close()
}

func TestRetrWithoutDataConnection(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("RETR hello.txt")
	c.expect(425, "Use PORT or PASV first")
}

func TestPortSyntaxErrors(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("PORT 1,2,3")
	c.expect(501)
	c.cmd("PORT 1,2,3,4,5,999")
	c.expect(501)
	c.cmd("PORT a,b,c,d,e,f")
	c.expect(501)
	c.cmd("PORT 127,0,0,1,0,0")
	c.expect(501)
}

func TestEprtActiveMode(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	c.cmd("EPRT |1|127.0.0.1|%d|", port)
	c.expect(200, "EPRT command successful")

	c.cmd("RETR hello.txt")
	c.expect(150)
	if got := readDataConn(t, c, ln); got != "hello world\n" {
		t.Errorf("RETR data = %q", got)
	}
	c.expect(226)
}

func TestEprtSyntaxErrors(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("EPRT |1|127.0.0.1|1234") // missing trailing delimiter
	c.expect(501)
	c.cmd("EPRT |3|127.0.0.1|1234|") // unsupported protocol
	c.expect(522)
	c.cmd("EPRT |1|not-an-ip|1234|") // bad address
	c.expect(501)
	c.cmd("EPRT |1|127.0.0.1|0|") // bad port
	c.expect(501)
	c.cmd("EPRT") // missing argument
	c.expect(501)
}

// --- Listing (active mode) ---------------------------------------------------------

func TestListActiveMode(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln := setupActiveMode(t, c)
	c.cmd("LIST")
	c.expect(150, "Here comes the directory listing")
	listing := readDataConn(t, c, ln)
	c.expect(226, "Directory send OK")

	for _, want := range []string{"hello.txt", "pub"} {
		if !strings.Contains(listing, want) {
			t.Errorf("LIST output missing %q:\n%s", want, listing)
		}
	}
	// Unix-style listing: files start with '-', directories with 'd'.
	if !strings.Contains(listing, "-rw-r--r--") {
		t.Errorf("LIST output missing file mode line:\n%s", listing)
	}
	if !strings.Contains(listing, "drwxr-xr-x") {
		t.Errorf("LIST output missing directory mode line:\n%s", listing)
	}
}

func TestListSubdirectoryAndOptions(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	// LIST with an ls-style option argument is tolerated.
	ln := setupActiveMode(t, c)
	c.cmd("LIST -la /pub")
	c.expect(150)
	listing := readDataConn(t, c, ln)
	c.expect(226)
	if !strings.Contains(listing, "readme.md") || !strings.Contains(listing, "data.bin") {
		t.Errorf("LIST /pub output missing entries:\n%s", listing)
	}
	if strings.Contains(listing, "hello.txt") {
		t.Errorf("LIST /pub should not list root entries:\n%s", listing)
	}
}

func TestNlstActiveMode(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln := setupActiveMode(t, c)
	c.cmd("NLST")
	c.expect(150)
	names := readDataConn(t, c, ln)
	c.expect(226)

	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimRight(names, "\r\n"), "\r\n") {
		got[line] = true
	}
	for _, want := range []string{"hello.txt", "pub"} {
		if !got[want] {
			t.Errorf("NLST output missing %q, got:\n%s", want, names)
		}
	}
	// NLST returns names only: no ls-style metadata.
	if strings.Contains(names, "rw-r--r--") {
		t.Errorf("NLST output contains metadata lines:\n%s", names)
	}
}

func TestListNotFound(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	ln := setupActiveMode(t, c)
	c.cmd("LIST /missing-dir")
	c.expect(550, "No such file or directory")
	ln.Close()
}

// --- Passive mode --------------------------------------------------------------------

// enablePassive configures a passive port range based on a free ephemeral port.
func enablePassive(cfg *config.Config) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	cfg.PassiveEnabled = true
	cfg.PassivePortMin = base
	cfg.PassivePortMax = base + 20
}

func TestPassiveModeDisabledByDefault(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("PASV")
	c.expect(502, "Passive mode disabled")
	c.cmd("EPSV")
	c.expect(502, "Passive mode disabled")
}

func TestPassiveModeRetr(t *testing.T) {
	_, addr := startTestServer(t, enablePassive)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("PASV")
	lines := c.expect(227, "Entering Passive Mode (")
	var h1, h2, h3, h4, p1, p2 int
	if _, err := fmt.Sscanf(lines[0], "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
		&h1, &h2, &h3, &h4, &p1, &p2); err != nil {
		t.Fatalf("parse PASV reply %q: %v", lines[0], err)
	}
	port := p1*256 + p2

	// Connect the data channel before requesting the transfer.
	dc, err := net.DialTimeout("tcp", fmt.Sprintf("%d.%d.%d.%d:%d", h1, h2, h3, h4, port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial passive data channel: %v", err)
	}
	defer dc.Close()

	c.cmd("RETR hello.txt")
	c.expect(150)
	if got := readDataAll(t, dc); got != "hello world\n" {
		t.Errorf("RETR data = %q", got)
	}
	c.expect(226, "Transfer complete")
}

func TestPassiveModeEpsvAndNlst(t *testing.T) {
	_, addr := startTestServer(t, enablePassive)
	c := dialTestClient(t, addr)
	c.login()

	c.cmd("EPSV")
	lines := c.expect(229, "Entering Extended Passive Mode (|||")
	var port int
	if _, err := fmt.Sscanf(lines[0], "229 Entering Extended Passive Mode (|||%d|)", &port); err != nil {
		t.Fatalf("parse EPSV reply %q: %v", lines[0], err)
	}

	dc, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial passive data channel: %v", err)
	}
	defer dc.Close()

	c.cmd("NLST /pub")
	c.expect(150)
	names := readDataAll(t, dc)
	c.expect(226)
	if !strings.Contains(names, "readme.md") || !strings.Contains(names, "data.bin") {
		t.Errorf("NLST /pub via EPSV missing entries, got:\n%s", names)
	}
}

// --- IPv6 / dual-stack -----------------------------------------------------------------

func TestIPv6Connection(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "v6.txt", "over ipv6\n")

	cfg := config.Default()
	cfg.ListenAddr = "[::1]:0"
	cfg.ServeDir = dir
	cfg.Chroot = false
	cfg.ReadOnlyMount = false
	cfg.LogLevel = "error"

	srv, err := New(cfg)
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	go srv.Serve()
	t.Cleanup(srv.Close)
	addr := srv.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Skipf("cannot dial [::1]: %v", err)
	}
	c := &testClient{t: t, conn: conn, r: bufio.NewReader(conn)}
	code, _ := c.readReply()
	if code != 220 {
		t.Fatalf("greeting code = %d, want 220", code)
	}
	c.login()

	// Active-mode transfer over IPv6 via EPRT.
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("cannot listen on [::1]: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	c.cmd("EPRT |2|::1|%d|", port)
	c.expect(200)

	c.cmd("RETR v6.txt")
	c.expect(150)
	if got := readDataConn(t, c, ln); got != "over ipv6\n" {
		t.Errorf("RETR over IPv6 data = %q", got)
	}
	c.expect(226)
}

// --- Concurrency & lifecycle -----------------------------------------------------------

func TestConcurrentSessions(t *testing.T) {
	_, addr := startTestServer(t, nil)

	const clients = 5
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		go func() {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			c := &testClient{t: t, conn: conn, r: bufio.NewReader(conn)}
			code, _ := c.readReply()
			if code != 220 {
				errs <- fmt.Errorf("greeting = %d", code)
				return
			}
			c.cmd("USER anonymous")
			if code, _ := c.readReply(); code != 331 {
				errs <- fmt.Errorf("USER = %d", code)
				return
			}
			c.cmd("PASS x@y.z")
			if code, _ := c.readReply(); code != 230 {
				errs <- fmt.Errorf("PASS = %d", code)
				return
			}
			c.cmd("PWD")
			if code, _ := c.readReply(); code != 257 {
				errs <- fmt.Errorf("PWD = %d", code)
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < clients; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

func TestGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "hello.txt", "hello world\n")

	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.ServeDir = dir
	cfg.Chroot = false
	cfg.ReadOnlyMount = false
	cfg.LogLevel = "error"

	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	// A client is connected and logged in when shutdown starts.
	c := dialTestClient(t, srv.Addr().String())
	c.login()

	srv.Close()

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}

	// The client's connection is closed by the server.
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Fatal("expected client connection to be closed on shutdown")
	}

	// New connections are refused.
	if _, err := net.DialTimeout("tcp", srv.Addr().String(), time.Second); err == nil {
		t.Fatal("expected new connections to be refused after shutdown")
	}

	// Close is idempotent.
	srv.Close()
}
