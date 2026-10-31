// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/grisu48/rftp/cmd/rftp/ftp"
	"github.com/grisu48/rftp/cmd/rftp/logger"
)

// preLoginCommands may be used before USER/PASS completes.
var preLoginCommands = map[string]bool{
	ftp.CmdUSER: true,
	ftp.CmdPASS: true,
	ftp.CmdQUIT: true,
	ftp.CmdNOOP: true,
	ftp.CmdSYST: true,
	ftp.CmdFEAT: true,
	ftp.CmdHELP: true,
	ftp.CmdOPTS: true,
}

// handleCommand dispatches one parsed command to its handler.
func (s *Session) handleCommand(cmd ftp.Command) {
	if !preLoginCommands[cmd.Name] && !s.loggedIn {
		s.reply(ftp.R530NotLoggedIn, "Please login with USER and PASS")
		return
	}

	switch cmd.Name {
	// Connection & authentication
	case ftp.CmdUSER:
		s.cmdUser(cmd.Arg)
	case ftp.CmdPASS:
		s.cmdPass()
	case ftp.CmdQUIT:
		s.cmdQuit()
	case ftp.CmdNOOP:
		s.reply(ftp.R200CommandOK, "NOOP ok")

	// Navigation
	case ftp.CmdPWD, ftp.CmdXPWD:
		s.cmdPwd()
	case ftp.CmdCWD, ftp.CmdXCWD:
		s.cmdCwd(cmd.Arg)
	case ftp.CmdCDUP:
		s.cmdCdup()
	case ftp.CmdTYPE:
		s.cmdType(cmd.Arg)
	case ftp.CmdMODE:
		s.cmdMode(cmd.Arg)
	case ftp.CmdSTRU:
		s.cmdStru(cmd.Arg)

	// Information
	case ftp.CmdSYST:
		s.reply(ftp.R215SystemType, "UNIX Type: L8")
	case ftp.CmdFEAT:
		s.cmdFeat()
	case ftp.CmdHELP:
		s.cmdHelp()
	case ftp.CmdSIZE:
		s.cmdSize(cmd.Arg)
	case ftp.CmdMDTM:
		s.cmdMdtm(cmd.Arg)
	case ftp.CmdOPTS:
		s.cmdOpts(cmd.Arg)

	// Listing & retrieval
	case ftp.CmdLIST:
		s.cmdList(cmd.Arg, false)
	case ftp.CmdNLST:
		s.cmdList(cmd.Arg, true)
	case ftp.CmdRETR:
		s.cmdRetr(cmd.Arg)

	// Data connection setup
	case ftp.CmdPORT:
		s.cmdPort(cmd.Arg)
	case ftp.CmdEPRT:
		s.cmdEprt(cmd.Arg)
	case ftp.CmdLPRT:
		s.cmdLprt(cmd.Arg)
	case ftp.CmdPASV:
		s.cmdPasv()
	case ftp.CmdEPSV:
		s.cmdEpsv()

	// TLS is not supported (plain FTP only).
	case ftp.CmdAUTH, ftp.CmdPROT, ftp.CmdPBSZ:
		s.reply(ftp.R502NotImplemented, "TLS not supported")

	// Write operations are not supported (read-only file system).
	case ftp.CmdSTOR, ftp.CmdAPPE, ftp.CmdSTOU, ftp.CmdDELE,
		ftp.CmdRNFR, ftp.CmdRNTO, ftp.CmdMKD, ftp.CmdXMKD,
		ftp.CmdRMD, ftp.CmdXRMD, ftp.CmdSITE:
		logger.Warn("rejected write command remote=%s cmd=%s", s.remoteAddr, cmd.Name)
		s.reply(ftp.R550ActionNotTaken, "Read-only file system")

	// Recognized but not implemented. 502 (not 500) is essential here:
	// 500 means "command unrecognized" and breaks the fallback chains of
	// standard clients (e.g. the classic ftp client tries EPSV -> PASV ->
	// LPSV and EPRT -> PORT -> LPRT), while 502 tells them to fall back to
	// a supported command.
	case ftp.CmdMLSD, ftp.CmdMLST, ftp.CmdREST,
		ftp.CmdLPSV, ftp.CmdSTAT, ftp.CmdABOR, ftp.CmdALLO,
		ftp.CmdACCT, ftp.CmdSMNT, ftp.CmdREIN:
		s.reply(ftp.R502NotImplemented, "Command not implemented")

	default:
		s.reply(ftp.R500SyntaxError, "Command not recognized")
	}
}

// --- Connection & authentication -------------------------------------------

// cmdUser accepts only the anonymous user names "anonymous" and "ftp";
// anything else is rejected and the connection is closed.
func (s *Session) cmdUser(arg string) {
	if arg == "" {
		s.reply(ftp.R501SyntaxErrorParams, "Username required")
		return
	}
	name := strings.ToLower(arg)
	if name != "anonymous" && name != "ftp" {
		logger.Warn("rejected non-anonymous login remote=%s user=%s", s.remoteAddr, arg)
		s.reply(ftp.R530NotLoggedIn, "Anonymous access only")
		s.quit = true
		return
	}
	s.user = name
	s.loggedIn = false
	s.reply(ftp.R331NeedPassword, "Anonymous login ok, send your complete email address as your password")
}

// cmdPass accepts any password for the anonymous user.
func (s *Session) cmdPass() {
	if s.user == "" {
		s.reply(ftp.R503BadSequence, "Login with USER first")
		return
	}
	s.loggedIn = true
	s.cwd = "/"
	logger.Info("anonymous login remote=%s user=%s", s.remoteAddr, s.user)
	s.reply(ftp.R230LoggedIn, "Anonymous access granted")
}

func (s *Session) cmdQuit() {
	s.reply(ftp.R221Goodbye, "Goodbye")
	s.quit = true
}

// --- Navigation --------------------------------------------------------------

func (s *Session) cmdPwd() {
	// RFC 959: double any embedded quotes in the path.
	quoted := strings.ReplaceAll(s.cwd, `"`, `""`)
	s.reply(ftp.R257Pathname, "\"%s\" is the current directory", quoted)
}

func (s *Session) cmdCwd(arg string) {
	if arg == "" {
		s.reply(ftp.R501SyntaxErrorParams, "Directory name required")
		return
	}
	target, err := resolvePath(s.cwd, arg)
	if err != nil {
		logger.Warn("path traversal blocked remote=%s path=%s", s.remoteAddr, arg)
		s.reply(ftp.R550ActionNotTaken, "Access denied")
		return
	}
	// Stat through the os.Root scoped to the served root, so the access
	// cannot be raced by a symlink swap (no TOCTOU window).
	root, name, _, err := s.scoped(target)
	if err != nil {
		s.replyPathError(err)
		return
	}
	defer root.Close()
	info, err := root.Stat(name)
	if err != nil {
		s.reply(ftp.R550ActionNotTaken, "No such file or directory")
		return
	}
	if !info.IsDir() {
		s.reply(ftp.R550ActionNotTaken, "Not a directory")
		return
	}
	s.cwd = target
	s.reply(ftp.R250ActionOK, "Directory changed to %s", target)
}

// cmdCdup changes to the parent directory; at the root it stays at the root.
func (s *Session) cmdCdup() {
	if s.cwd == "/" {
		s.reply(ftp.R250ActionOK, "Directory changed to /")
		return
	}
	target, err := resolvePath(s.cwd, "..")
	if err != nil {
		s.reply(ftp.R550ActionNotTaken, "Access denied")
		return
	}
	s.cwd = target
	s.reply(ftp.R250ActionOK, "Directory changed to %s", target)
}

func (s *Session) cmdType(arg string) {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		s.reply(ftp.R501SyntaxErrorParams, "Type required")
		return
	}
	switch strings.ToUpper(fields[0]) {
	case "A":
		s.typ = ftp.TypeASCII
		s.reply(ftp.R200CommandOK, "Type set to ASCII")
	case "I", "L":
		// "L 8" is binary; only 8-bit bytes are supported.
		if strings.ToUpper(fields[0]) == "L" && (len(fields) < 2 || fields[1] != "8") {
			s.reply(ftp.R504NotImplementedParam, "Only L 8 is supported")
			return
		}
		s.typ = ftp.TypeImage
		s.reply(ftp.R200CommandOK, "Type set to Image")
	default:
		s.reply(ftp.R504NotImplementedParam, "Type not supported")
	}
}

func (s *Session) cmdMode(arg string) {
	if strings.ToUpper(strings.TrimSpace(arg)) == "S" {
		s.reply(ftp.R200CommandOK, "Mode set to stream")
		return
	}
	s.reply(ftp.R504NotImplementedParam, "Only stream mode is supported")
}

func (s *Session) cmdStru(arg string) {
	if strings.ToUpper(strings.TrimSpace(arg)) == "F" {
		s.reply(ftp.R200CommandOK, "Structure set to file")
		return
	}
	s.reply(ftp.R504NotImplementedParam, "Only file structure is supported")
}

// --- Information -------------------------------------------------------------

func (s *Session) cmdFeat() {
	// EPRT (active mode) is always available. EPSV/PASV (passive mode)
	// are only advertised when passive mode is enabled, so that clients
	// do not attempt passive connections that would be rejected with 502.
	features := []string{"Features:", " UTF8", " TVFS", " SIZE", " MDTM", " EPRT", "End"}
	if s.srv.cfg.PassiveEnabled {
		features = append(features[:len(features)-1], " EPSV", " PASV", "End")
	}
	s.replyLines(ftp.R211SystemStatus, features)
}

func (s *Session) cmdHelp() {
	s.replyLines(ftp.R214HelpMessage, []string{
		"The following commands are recognized:",
		" USER PASS QUIT NOOP SYST FEAT HELP OPTS",
		" PWD CWD CDUP TYPE MODE STRU",
		" LIST NLST RETR SIZE MDTM",
		" PORT EPRT PASV EPSV",
		"Help OK",
	})
}

// cmdSize returns the size of a regular file (RFC 959: 213 <size>).
func (s *Session) cmdSize(arg string) {
	if arg == "" {
		s.reply(ftp.R501SyntaxErrorParams, "Filename required")
		return
	}
	info, ok := s.resolveFile(arg)
	if !ok {
		return
	}
	if !info.Mode().IsRegular() {
		s.reply(ftp.R550ActionNotTaken, "Not a regular file")
		return
	}
	s.reply(ftp.R213FileStatus, "%d", info.Size())
}

// cmdMdtm returns the modification time of a file (RFC 959: 213 YYYYMMDDHHMMSS).
func (s *Session) cmdMdtm(arg string) {
	if arg == "" {
		s.reply(ftp.R501SyntaxErrorParams, "Filename required")
		return
	}
	info, ok := s.resolveFile(arg)
	if !ok {
		return
	}
	s.reply(ftp.R213FileStatus, "%s", info.ModTime().UTC().Format("20060102150405"))
}

func (s *Session) cmdOpts(arg string) {
	fields := strings.Fields(strings.ToUpper(arg))
	if len(fields) == 2 && fields[0] == "UTF8" && (fields[1] == "ON" || fields[1] == "OFF") {
		if fields[1] == "ON" {
			s.reply(ftp.R200CommandOK, "UTF8 support enabled")
		} else {
			s.reply(ftp.R200CommandOK, "UTF8 support disabled")
		}
		return
	}
	s.reply(ftp.R501SyntaxErrorParams, "Option not understood")
}

// --- Listing & retrieval -----------------------------------------------------

// cmdList implements LIST (full listing) and NLST (names only).
func (s *Session) cmdList(arg string, namesOnly bool) {
	// Tolerate ls-style options ("LIST -la /pub"): ignore leading "-..." fields.
	target := ""
	for _, f := range strings.Fields(arg) {
		if !strings.HasPrefix(f, "-") {
			target = f
		}
	}
	virtual, err := resolvePath(s.cwd, target)
	if err != nil {
		logger.Warn("path traversal blocked remote=%s path=%s", s.remoteAddr, arg)
		s.reply(ftp.R550ActionNotTaken, "Access denied")
		return
	}
	// Access the directory through the os.Root scoped to the served root, so
	// a symlink swap between the policy check and the access cannot escape.
	root, name, _, err := s.scoped(virtual)
	if err != nil {
		s.replyPathError(err)
		return
	}
	defer root.Close()
	info, err := root.Stat(name)
	if err != nil {
		s.reply(ftp.R550ActionNotTaken, "No such file or directory")
		return
	}

	dc, err := s.openDataConn()
	if err != nil {
		s.replyDataConnError(err)
		return
	}
	defer dc.Close()

	s.reply(ftp.R150FileActionPending, "Here comes the directory listing")

	if info.IsDir() {
		entries, err := fs.ReadDir(root.FS(), name)
		if err != nil {
			s.reply(ftp.R550ActionNotTaken, "Cannot list directory")
			return
		}
		for _, entry := range entries {
			if namesOnly {
				fmt.Fprintf(dc, "%s\r\n", entry.Name())
				continue
			}
			ei, err := entry.Info()
			if err != nil {
				continue
			}
			fmt.Fprintf(dc, "%s\r\n", formatListLine(ei, entry.Name()))
		}
	} else {
		if namesOnly {
			fmt.Fprintf(dc, "%s\r\n", info.Name())
		} else {
			fmt.Fprintf(dc, "%s\r\n", formatListLine(info, info.Name()))
		}
	}

	s.reply(ftp.R226TransferComplete, "Directory send OK")
}

// cmdRetr transfers a file to the client over the data connection.
func (s *Session) cmdRetr(arg string) {
	if arg == "" {
		s.reply(ftp.R501SyntaxErrorParams, "Filename required")
		return
	}
	virtual, err := resolvePath(s.cwd, arg)
	if err != nil {
		logger.Warn("path traversal blocked remote=%s path=%s", s.remoteAddr, arg)
		s.reply(ftp.R550ActionNotTaken, "Access denied")
		return
	}
	// Stat and open through the os.Root scoped to the served root, so the
	// access cannot escape even if a symlink is swapped in after the check.
	root, name, _, err := s.scoped(virtual)
	if err != nil {
		s.replyPathError(err)
		return
	}
	defer root.Close()
	info, err := root.Stat(name)
	if err != nil {
		s.reply(ftp.R550ActionNotTaken, "No such file or directory")
		return
	}
	if !info.Mode().IsRegular() {
		s.reply(ftp.R550ActionNotTaken, "Not a regular file")
		return
	}
	f, err := root.Open(name)
	if err != nil {
		s.reply(ftp.R550ActionNotTaken, "Cannot open file")
		return
	}
	defer f.Close()

	dc, err := s.openDataConn()
	if err != nil {
		s.replyDataConnError(err)
		return
	}
	defer dc.Close()

	s.reply(ftp.R150FileActionPending, "Opening BINARY mode data connection for %s (%d bytes)",
		filepath.Base(virtual), info.Size())
	if _, err := io.Copy(dc, f); err != nil {
		s.reply(ftp.R426TransferAborted, "Transfer aborted")
		return
	}
	s.reply(ftp.R226TransferComplete, "Transfer complete")
}

// --- Data connection setup ---------------------------------------------------

// cmdPort implements IPv4 active mode: PORT h1,h2,h3,h4,p1,p2.
func (s *Session) cmdPort(arg string) {
	parts := strings.Split(arg, ",")
	if len(parts) != 6 {
		s.reply(ftp.R501SyntaxErrorParams, "Syntax error in PORT command")
		return
	}
	nums := make([]int, 6)
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			s.reply(ftp.R501SyntaxErrorParams, "Syntax error in PORT command")
			return
		}
		nums[i] = n
	}
	port := nums[4]*256 + nums[5]
	if port == 0 {
		s.reply(ftp.R501SyntaxErrorParams, "Syntax error in PORT command")
		return
	}
	ip := net.IPv4(byte(nums[0]), byte(nums[1]), byte(nums[2]), byte(nums[3])) // #nosec G115 -- nums[i] range-checked to 0..255 above
	if !s.checkDataAddr(ip) {
		// Anti-FTP-bounce: the data address must be the control peer itself.
		logger.Warn("rejected PORT to foreign host remote=%s addr=%s", s.remoteAddr, ip)
		s.reply(ftp.R501SyntaxErrorParams, "PORT address must match the control connection")
		return
	}
	s.setActive(&net.TCPAddr{IP: ip, Port: port})
	s.reply(ftp.R200CommandOK, "PORT command successful")
}

// cmdEprt implements extended active mode: EPRT |<proto>|<addr>|<port>|.
func (s *Session) cmdEprt(arg string) {
	if len(arg) < 2 {
		s.reply(ftp.R501SyntaxErrorParams, "Syntax error in EPRT command")
		return
	}
	delim := string(arg[0])
	parts := strings.Split(arg[1:], delim)
	// Expect: <proto>|<addr>|<port>| -> 4 fields with an empty last one.
	if len(parts) != 4 || parts[3] != "" {
		s.reply(ftp.R501SyntaxErrorParams, "Syntax error in EPRT command")
		return
	}
	proto, addrStr, portStr := parts[0], parts[1], parts[2]

	var ip net.IP
	switch proto {
	case "1":
		ip = net.ParseIP(addrStr).To4()
		if ip == nil {
			s.reply(ftp.R501SyntaxErrorParams, "Syntax error in EPRT command")
			return
		}
	case "2":
		ip = net.ParseIP(addrStr)
		if ip == nil || ip.To4() != nil {
			s.reply(ftp.R501SyntaxErrorParams, "Syntax error in EPRT command")
			return
		}
	default:
		s.reply(ftp.R522ProtocolNotSupported, "Network protocol not supported, use (1,2)")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		s.reply(ftp.R501SyntaxErrorParams, "Syntax error in EPRT command")
		return
	}
	if !s.checkDataAddr(ip) {
		// Anti-FTP-bounce: the data address must be the control peer itself.
		logger.Warn("rejected EPRT to foreign host remote=%s addr=%s", s.remoteAddr, ip)
		s.reply(ftp.R501SyntaxErrorParams, "EPRT address must match the control connection")
		return
	}
	s.setActive(&net.TCPAddr{IP: ip, Port: port})
	s.reply(ftp.R200CommandOK, "EPRT command successful")
}

// cmdLprt implements RFC 1639 extended active mode with long addresses:
//
//	LPRT <af>,<hal>,<h1>,...,<hN>,<pal>,<p1>,<p2>
//
// The address family is determined by the address length (hal): 4 = IPv4,
// 16 = IPv6. Real-world clients send af=4/af=6 (the IP version number), so
// af is validated loosely (1/2/4/6) and cross-checked against hal.
// Standard clients need LPRT in their fallback chain: after EPSV fails they
// skip EPRT and try LPRT (e.g. the classic ftp client over IPv6).
func (s *Session) cmdLprt(arg string) {
	fail := func() {
		s.reply(ftp.R501SyntaxErrorParams, "Syntax error in LPRT command")
	}
	fields := strings.Split(arg, ",")
	if len(fields) < 5 {
		fail()
		return
	}
	af, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil || (af != 1 && af != 2 && af != 4 && af != 6) {
		fail()
		return
	}
	hal, err := strconv.Atoi(strings.TrimSpace(fields[1]))
	if err != nil || (hal != 4 && hal != 16) {
		fail()
		return
	}
	// af and hal must agree on the address family (1/4 = IPv4, 2/6 = IPv6).
	if (hal == 16) != (af == 2 || af == 6) {
		fail()
		return
	}
	// af, hal, hal address bytes, pal, pal port bytes.
	if len(fields) != 5+hal {
		fail()
		return
	}
	pal, err := strconv.Atoi(strings.TrimSpace(fields[2+hal]))
	if err != nil || pal != 2 {
		fail()
		return
	}
	addrBytes := make([]byte, hal)
	for i := 0; i < hal; i++ {
		n, err := strconv.Atoi(strings.TrimSpace(fields[2+i]))
		if err != nil || n < 0 || n > 255 {
			fail()
			return
		}
		addrBytes[i] = byte(n) // #nosec G115 -- n range-checked to 0..255 above
	}
	var ip net.IP
	if hal == 4 {
		ip = net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
	} else {
		ip = net.IP(addrBytes)
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(fields[3+hal]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(fields[4+hal]))
	if err1 != nil || err2 != nil || p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255 {
		fail()
		return
	}
	port := p1*256 + p2
	if port == 0 {
		fail()
		return
	}
	if !s.checkDataAddr(ip) {
		// Anti-FTP-bounce: the data address must be the control peer itself.
		logger.Warn("rejected LPRT to foreign host remote=%s addr=%s", s.remoteAddr, ip)
		s.reply(ftp.R501SyntaxErrorParams, "LPRT address must match the control connection")
		return
	}
	s.setActive(&net.TCPAddr{IP: ip, Port: port})
	s.reply(ftp.R200CommandOK, "LPRT command successful")
}

// cmdPasv implements IPv4 passive mode: PASV -> 227 (h1,h2,h3,h4,p1,p2).
func (s *Session) cmdPasv() {
	if !s.srv.cfg.PassiveEnabled {
		s.reply(ftp.R502NotImplemented, "Passive mode disabled")
		return
	}
	local, ok := s.conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		s.reply(ftp.R425NoDataConnection, "Cannot open passive connection")
		return
	}
	ip4 := local.IP.To4()
	if ip4 == nil {
		s.reply(ftp.R522ProtocolNotSupported, "PASV requires an IPv4 connection, use EPSV")
		return
	}
	ln, err := s.srv.pasv.Listen(ip4)
	if err != nil {
		logger.Warn("cannot open passive listener remote=%s error=%v", s.remoteAddr, err)
		s.reply(ftp.R425NoDataConnection, "Cannot open passive connection")
		return
	}
	s.setPassive(ln)
	port := ln.Addr().(*net.TCPAddr).Port
	s.reply(ftp.R227PassiveMode, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
		ip4[0], ip4[1], ip4[2], ip4[3], port>>8, port&0xff)
}

// cmdEpsv implements extended passive mode: EPSV -> 229 (|||port|).
func (s *Session) cmdEpsv() {
	if !s.srv.cfg.PassiveEnabled {
		s.reply(ftp.R502NotImplemented, "Passive mode disabled")
		return
	}
	local, ok := s.conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		s.reply(ftp.R425NoDataConnection, "Cannot open passive connection")
		return
	}
	ln, err := s.srv.pasv.Listen(local.IP)
	if err != nil {
		logger.Warn("cannot open passive listener remote=%s error=%v", s.remoteAddr, err)
		s.reply(ftp.R425NoDataConnection, "Cannot open passive connection")
		return
	}
	s.setPassive(ln)
	port := ln.Addr().(*net.TCPAddr).Port
	s.reply(ftp.R229ExtPassiveMode, "Entering Extended Passive Mode (|||%d|)", port)
}

// --- Helpers -----------------------------------------------------------------

// resolveFile resolves a client path and stats it through the os.Root scoped
// to the served root (so the access cannot escape it), sending the
// appropriate error reply when it fails. It reports whether the caller
// should continue.
func (s *Session) resolveFile(arg string) (info os.FileInfo, ok bool) {
	virtual, err := resolvePath(s.cwd, arg)
	if err != nil {
		logger.Warn("path traversal blocked remote=%s path=%s", s.remoteAddr, arg)
		s.reply(ftp.R550ActionNotTaken, "Access denied")
		return nil, false
	}
	root, name, _, err := s.scoped(virtual)
	if err != nil {
		s.replyPathError(err)
		return nil, false
	}
	defer root.Close()
	info, err = root.Stat(name)
	if err != nil {
		s.reply(ftp.R550ActionNotTaken, "No such file or directory")
		return nil, false
	}
	return info, true
}

// replyPathError maps a path resolution error to an FTP reply.
func (s *Session) replyPathError(err error) {
	if errors.Is(err, errAccessDenied) {
		s.reply(ftp.R550ActionNotTaken, "Access denied")
		return
	}
	s.reply(ftp.R550ActionNotTaken, "No such file or directory")
}

// replyDataConnError maps a data connection error to an FTP reply.
func (s *Session) replyDataConnError(err error) {
	if errors.Is(err, errNoDataConn) {
		s.reply(ftp.R425NoDataConnection, "Use PORT or PASV first")
		return
	}
	logger.Warn("data connection failed remote=%s error=%v", s.remoteAddr, err)
	s.reply(ftp.R425NoDataConnection, "Cannot open data connection")
}

// formatListLine renders one Unix-style "ls -l" line for a directory entry.
func formatListLine(info os.FileInfo, name string) string {
	return fmt.Sprintf("%s %3d %-8s %-8s %8d %s %s",
		info.Mode().String(),
		1,
		"ftp",
		"ftp",
		info.Size(),
		info.ModTime().Format("Jan 02 15:04"),
		name,
	)
}
