package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"anonftp/cmd/rftp/config"
	"anonftp/cmd/rftp/logger"
)

func TestMain(m *testing.M) {
	// Keep test output clean.
	logger.SetLevel("error")
	os.Exit(m.Run())
}

// testClient is a minimal FTP client used by the integration tests.
type testClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

// startTestServer creates a server on 127.0.0.1 with an ephemeral port,
// serving a temp directory populated with test files, and starts its
// accept loop. mutate can adjust the config (e.g. enable passive mode).
func startTestServer(t *testing.T, mutate func(*config.Config)) (*Server, string) {
	t.Helper()

	dir := t.TempDir()
	writeTestFile(t, dir, "hello.txt", "hello world\n")
	writeTestFile(t, dir, "pub/readme.md", "# readme\n")
	writeTestFile(t, dir, "pub/data.bin", "\x00\x01\x02\x03")

	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.ServeDir = dir
	cfg.Chroot = false
	cfg.ReadOnlyMount = false
	cfg.LogLevel = "error"
	if mutate != nil {
		mutate(cfg)
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	go srv.Serve()
	t.Cleanup(srv.Close)
	return srv, srv.Addr().String()
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := dir + "/" + name
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// dialTestClient connects and consumes the 220 greeting.
func dialTestClient(t *testing.T, addr string) *testClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	c := &testClient{t: t, conn: conn, r: bufio.NewReader(conn)}
	code, lines := c.readReply()
	if code != 220 {
		t.Fatalf("greeting code = %d, want 220 (lines: %v)", code, lines)
	}
	return c
}

// readReply reads one (possibly multi-line) FTP reply and returns its code
// and raw lines.
func (c *testClient) readReply() (int, []string) {
	c.t.Helper()
	var lines []string
	for {
		c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read reply: %v (got so far: %v)", err, lines)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		// A reply is complete on a line of the form "ddd " (code + space).
		if len(line) >= 4 && line[3] == ' ' {
			code, err := strconv.Atoi(line[:3])
			if err != nil {
				c.t.Fatalf("bad reply line %q: %v", line, err)
			}
			return code, lines
		}
		if len(line) < 4 {
			c.t.Fatalf("malformed reply line %q", line)
		}
	}
}

// cmd sends a command without reading the reply; use expect or readReply
// to consume the response.
func (c *testClient) cmd(format string, args ...any) {
	c.t.Helper()
	if _, err := fmt.Fprintf(c.conn, format+"\r\n", args...); err != nil {
		c.t.Fatalf("send command: %v", err)
	}
}

// expect checks that the last command produced the wanted code and that the
// reply text contains all the wanted substrings.
func (c *testClient) expect(code int, wantSubstrings ...string) []string {
	c.t.Helper()
	gotCode, lines := c.readReply()
	if gotCode != code {
		c.t.Fatalf("reply code = %d, want %d (lines: %v)", gotCode, code, lines)
	}
	joined := strings.Join(lines, "\n")
	for _, sub := range wantSubstrings {
		if !strings.Contains(joined, sub) {
			c.t.Fatalf("reply %v does not contain %q", lines, sub)
		}
	}
	return lines
}

// login performs an anonymous login and verifies the replies.
func (c *testClient) login() {
	c.t.Helper()
	c.cmd("USER anonymous")
	c.expect(331, "Anonymous login ok")
	c.cmd("PASS guest@example.com")
	c.expect(230, "Anonymous access granted")
}

// readDataAll reads everything from conn until EOF.
func readDataAll(t *testing.T, conn net.Conn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
