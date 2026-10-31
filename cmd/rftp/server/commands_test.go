// SPDX-License-Identifier: MIT

package server

import (
	"bufio"
	"hash/crc32"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grisu48/rftp/cmd/rftp/ftp"
)

// TestAllowlistClassifiesEveryCommand verifies the allowlist invariant: every
// command constant defined in the ftp package is classified in exactly one
// bucket — allowed, or rejected (write / TLS / not-implemented) — and the
// allowed set is disjoint from all rejection sets. A new command constant
// added to ftp/protocol.go without being classified here fails this test.
func TestAllowlistClassifiesEveryCommand(t *testing.T) {
	data, err := os.ReadFile("../ftp/protocol.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`Cmd\w+\s*=\s*"([A-Z0-9]+)"`)
	matches := re.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		t.Fatal("no command constants found in ftp/protocol.go")
	}

	classified := func(name string) int {
		n := 0
		if allowedCommands[name] {
			n++
		}
		if writeCommands[name] {
			n++
		}
		if tlsCommands[name] {
			n++
		}
		if notImplementedCommands[name] {
			n++
		}
		return n
	}

	for _, m := range matches {
		name := string(m[1])
		if n := classified(name); n != 1 {
			t.Errorf("command %s is classified %d times, want exactly 1 (allowed XOR rejected)", name, n)
		}
	}

	// Every filesystem-modifying RFC 959 command (plus X-aliases and SITE)
	// must be rejected as a write command, never allowed.
	for _, name := range []string{
		ftp.CmdSTOR, ftp.CmdAPPE, ftp.CmdSTOU, ftp.CmdDELE,
		ftp.CmdRNFR, ftp.CmdRNTO, ftp.CmdMKD, ftp.CmdXMKD,
		ftp.CmdRMD, ftp.CmdXRMD, ftp.CmdSITE,
	} {
		if allowedCommands[name] {
			t.Errorf("write command %s must not be in allowedCommands", name)
		}
		if !writeCommands[name] {
			t.Errorf("write command %s is not in writeCommands", name)
		}
	}

	// preLoginCommands must be a subset of allowedCommands: the login gate
	// runs after the allowlist guard.
	for name := range preLoginCommands {
		if !allowedCommands[name] {
			t.Errorf("pre-login command %s is not in allowedCommands", name)
		}
	}
}

// TestRejectedCommandsNeverDispatched feeds every rejected command straight
// into handleCommand — both before and after login — and requires the
// RFC-mandated rejection code. The allowlist guard at the top of
// handleCommand runs before the login check and before the dispatch switch,
// so no rejected command can reach a handler.
func TestRejectedCommandsNeverDispatched(t *testing.T) {
	want := map[string]int{}
	for name := range writeCommands {
		want[name] = 550
	}
	for name := range tlsCommands {
		want[name] = 502
	}
	for name := range notImplementedCommands {
		want[name] = 502
	}
	want["FOOBAR"] = 500 // completely unknown command

	for _, loggedIn := range []bool{false, true} {
		for name, code := range want {
			serverEnd, clientEnd := net.Pipe()
			s := &Session{
				srv:        &Server{},
				conn:       serverEnd,
				r:          bufio.NewReader(serverEnd),
				remoteAddr: "test-peer",
				loggedIn:   loggedIn,
			}
			done := make(chan struct{})
			go func() {
				s.handleCommand(ftp.Command{Name: name, Arg: "evil.txt"})
				close(done)
			}()
			_ = clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(clientEnd).ReadString('\n')
			if err != nil {
				t.Fatalf("cmd=%s loggedIn=%v: no reply: %v", name, loggedIn, err)
			}
			<-done
			_ = serverEnd.Close()
			_ = clientEnd.Close()
			line = strings.TrimRight(line, "\r\n")
			if !strings.HasPrefix(line, strconv.Itoa(code)+" ") {
				t.Errorf("cmd=%s loggedIn=%v: reply = %q, want code %d", name, loggedIn, line, code)
			}
		}
	}
}

// TestWriteCommandsRejectedVariants sends write commands in evasion variants
// (case, whitespace, separators, paths) over a real connection and requires
// that every one is rejected — never executed.
func TestWriteCommandsRejectedVariants(t *testing.T) {
	srv, addr := startTestServer(t, nil)

	// Snapshot the served tree before the attack.
	before := snapshotTree(t, srv.cfg.ServeDir)

	c := dialTestClient(t, addr)
	c.login()

	variants := []string{
		"stor evil.txt",          // lowercase
		"StOr evil.txt",          // mixed case
		"   STOR evil.txt",       // leading spaces
		"STOR  evil.txt",         // double space
		"STOR",                   // no argument
		"STOR /tmp/evil-abs.txt", // absolute path outside the root
		"STOR ../../evil.txt",    // traversal
		"DELE hello.txt",
		"APPE ../../evil.txt",
		"STOU /tmp/evil-stou",
		"RNFR hello.txt",  // rename sequence ...
		"RNTO stolen.txt", // ... must not complete
		"MKD ../../evil-dir",
		"XMKD evil-dir",
		"RMD /",
		"XRMD pub",
		"SITE CHMOD 777 hello.txt",
		"SITE",
	}
	for _, v := range variants {
		c.cmd("%s", v)
		code, lines := c.readReply()
		if code == 200 || code == 250 || code == 226 || code == 150 {
			t.Fatalf("write variant %q was ACCEPTED: %v", v, lines)
		}
		if code != 550 && code != 500 {
			t.Fatalf("write variant %q: reply code = %d, want 550 or 500 (lines: %v)", v, code, lines)
		}
	}

	// A tab-separated verb does not parse as the command; it must be
	// rejected as unrecognized, never executed.
	if _, err := c.conn.Write([]byte("STOR\tevil.txt\r\n")); err != nil {
		t.Fatal(err)
	}
	code, lines := c.readReply()
	if code != 500 && code != 550 {
		t.Fatalf("tab-separated STOR: reply code = %d, want 500 or 550 (lines: %v)", code, lines)
	}

	// The session must still be usable afterwards.
	c.cmd("NOOP")
	c.expect(200)
	c.cmd("QUIT")
	c.expect(221)

	// The served tree must be completely unchanged.
	after := snapshotTree(t, srv.cfg.ServeDir)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("served tree changed by rejected write commands:\nbefore:\n%s\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	// And nothing may have been created outside the served root either.
	for _, p := range []string{"/tmp/evil-abs.txt", "/tmp/evil-stou", "/tmp/rftp-audit/evil.txt", "/evil.txt"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("write command created a file outside the served root: %s", p)
		}
	}
}

// TestWriteCommandsRejectedPreLogin verifies that write commands are rejected
// even before USER/PASS completes (with 550, not merely 530).
func TestWriteCommandsRejectedPreLogin(t *testing.T) {
	_, addr := startTestServer(t, nil)
	c := dialTestClient(t, addr)
	for name := range writeCommands {
		c.cmd("%s evil.txt", name)
		c.expect(550, "Read-only file system")
	}
	c.cmd("QUIT")
	c.expect(221)
}

// TestCommandSurfaceClassification sends every RFC 959 command (plus the
// supported extensions) to a logged-in session and checks that each one is
// explicitly classified: read commands succeed (2xx), write commands are
// rejected with 550, recognized-but-unimplemented and TLS commands with 502,
// and a completely unknown command with 500.
func TestCommandSurfaceClassification(t *testing.T) {
	_, addr := startTestServer(t, nil) // passive mode disabled by default
	c := dialTestClient(t, addr)
	c.login()

	ok := []struct {
		cmd  string
		code int
	}{
		{ftp.CmdPWD, 257}, {ftp.CmdXPWD, 257},
		{ftp.CmdCWD + " /", 250}, {ftp.CmdXCWD + " /", 250}, {ftp.CmdCDUP, 250},
		{ftp.CmdTYPE + " I", 200}, {ftp.CmdMODE + " S", 200}, {ftp.CmdSTRU + " F", 200},
		{ftp.CmdSYST, 215}, {ftp.CmdFEAT, 211}, {ftp.CmdHELP, 214},
		{ftp.CmdOPTS + " UTF8 ON", 200}, {ftp.CmdNOOP, 200},
		{ftp.CmdSIZE + " hello.txt", 213}, {ftp.CmdMDTM + " hello.txt", 213},
		{ftp.CmdPORT + " 127,0,0,1,200,10", 200},
		{ftp.CmdEPRT + " |1|127.0.0.1|5001|", 200},
		{ftp.CmdLPRT + " 4,4,127,0,0,1,2,19,137", 200},
	}
	for _, e := range ok {
		c.cmd("%s", e.cmd)
		c.expect(e.code)
	}

	notImplemented := []string{
		ftp.CmdLPSV, ftp.CmdSTAT, ftp.CmdABOR, ftp.CmdALLO + " 100",
		ftp.CmdACCT + " x", ftp.CmdSMNT + " /", ftp.CmdREIN,
		ftp.CmdMLSD, ftp.CmdMLST + " hello.txt", ftp.CmdREST + " 0",
		ftp.CmdPASV, ftp.CmdEPSV, // passive mode disabled in the test config
		ftp.CmdAUTH + " TLS", ftp.CmdPROT + " P", ftp.CmdPBSZ + " 0",
	}
	for _, cmd := range notImplemented {
		c.cmd("%s", cmd)
		c.expect(502)
	}

	for name := range writeCommands {
		c.cmd("%s evil.txt", name)
		c.expect(550, "Read-only file system")
	}

	c.cmd("FOOBAR")
	c.expect(500, "Command not recognized")

	c.cmd("QUIT")
	c.expect(221)
}

// snapshotTree returns a sorted list of "path mode size content-hash" entries
// for everything under root, used to prove that rejected write commands did
// not modify anything.
func snapshotTree(t *testing.T, root string) []string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := rel + " " + info.Mode().String() + " " + strconv.FormatInt(info.Size(), 10)
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			entry += " " + strconv.FormatUint(uint64(crc32.ChecksumIEEE(data)), 10)
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	return entries
}
