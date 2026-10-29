# Implementation Tasks

## 1. Project Setup
- [ ] 1.1 Initialize Go module (`go mod init`)
- [ ] 1.2 Add YAML dependency (`gopkg.in/yaml.v3`)
- [ ] 1.3 Create directory structure
- [ ] 1.4 Add `.gitignore` (binary, config examples)
- [ ] 1.5 Create `main.go` with basic flag parsing

## 2. Configuration
- [ ] 2.1 Define config struct with YAML tags
- [ ] 2.2 Implement config file loading and validation
- [ ] 2.3 Add config defaults (passive disabled, sensible ports)
- [ ] 2.4 Validate serve directory exists and is readable
- [ ] 2.5 Add unit tests for config parsing

## 3. Security Layer
- [ ] 3.1 Implement chroot functionality (`security/chroot.go`)
- [ ] 3.2 Implement privilege dropping (`security/privileges.go`)
- [ ] 3.3 Implement read-only mount (`security/mount.go`)
- [ ] 3.4 Create security initialization sequence (bind → chroot → mount → drop)
- [ ] 3.5 Add tests for privilege dropping (requires root, may need integration test)
- [ ] 3.6 Add tests for chroot behavior

## 4. FTP Server Core
- [ ] 4.1 Create TCP listener with dual-stack support (`server/listener.go`)
- [ ] 4.2 Implement connection accept loop (`server/server.go`)
- [ ] 4.3 Create session structure for per-connection state (`server/session.go`)
- [ ] 4.4 Implement FTP command parser (line-based, CRLF handling)
- [ ] 4.5 Implement response writer (standard FTP response codes)

## 5. FTP Commands - Connection & Auth
- [ ] 5.1 Implement `USER` command (accept only "anonymous" or "ftp")
- [ ] 5.2 Implement `PASS` command (accept any password for anonymous)
- [ ] 5.3 Implement `QUIT` command
- [ ] 5.4 Implement `NOOP` command
- [ ] 5.5 Implement login state machine (require USER before PASS, etc.)

## 6. FTP Commands - Navigation
- [ ] 6.1 Implement `PWD` command
- [ ] 6.2 Implement `CWD` command (with path sanitization)
- [ ] 6.3 Implement `CDUP` command
- [ ] 6.4 Implement `TYPE` command (ASCII/Image)
- [ ] 6.5 Implement `MODE` and `STRU` commands (accept and ignore)

## 7. FTP Commands - Information
- [ ] 7.1 Implement `SYST` command
- [ ] 7.2 Implement `FEAT` command (advertise supported features)
- [ ] 7.3 Implement `HELP` command
- [ ] 7.4 Implement `SIZE` command
- [ ] 7.5 Implement `MDTM` command

## 8. FTP Commands - Listing & Retrieval
- [ ] 8.1 Implement `LIST` command (Unix-style listing)
- [ ] 8.2 Implement `NLST` command (name list)
- [ ] 8.3 Implement `RETR` command (file retrieval)
- [ ] 8.4 Add path traversal protection (prevent `../` escapes)
- [ ] 8.5 Add symlink handling policy (follow or reject?)

## 9. Data Transfer - Active Mode
- [ ] 9.1 Implement `PORT` command (IPv4 active mode)
- [ ] 9.2 Implement `EPRT` command (extended active mode, IPv6-capable)
- [ ] 9.3 Implement active data connection establishment

## 10. Data Transfer - Passive Mode (Optional)
- [ ] 10.1 Implement passive port range management (`server/passive.go`)
- [ ] 10.2 Implement `PASV` command (IPv4 passive mode)
- [ ] 10.3 Implement `EPSV` command (extended passive mode, IPv6-capable)
- [ ] 10.4 Implement passive listener lifecycle
- [ ] 10.5 Add passive mode enable/disable based on config

## 11. Logging
- [ ] 11.1 Implement structured logger (stdout/stderr)
- [ ] 11.2 Add connection logging (connect, disconnect, commands)
- [ ] 11.3 Add error logging with context
- [ ] 11.4 Add security event logging (auth attempts, path violations)

## 12. Signal Handling & Lifecycle
- [ ] 12.1 Implement graceful shutdown on SIGTERM/SIGINT
- [ ] 12.2 Close all active connections on shutdown
- [ ] 12.3 Add startup logging (config summary, security status)

## 13. Testing
- [ ] 13.1 Unit tests for config parsing
- [ ] 13.2 Unit tests for path sanitization
- [ ] 13.3 Unit tests for FTP command parsing
- [ ] 13.4 Integration test: basic anonymous login
- [ ] 13.5 Integration test: file retrieval
- [ ] 13.6 Integration test: directory listing
- [ ] 13.7 Integration test: passive mode (when enabled)
- [ ] 13.8 Integration test: IPv6 connectivity
- [ ] 13.9 Security test: verify write commands are rejected
- [ ] 13.10 Security test: verify path traversal is blocked

## 14. Documentation
- [ ] 14.1 Create `README.md` with usage instructions
- [ ] 14.2 Create example config file (`config.example.yaml`)
- [ ] 14.3 Document security model (chroot, privilege drop, read-only)
- [ ] 14.4 Document IPv4/IPv6 setup
- [ ] 14.5 Add deployment notes (systemd unit example)

## 15. Build & Distribution
- [ ] 15.1 Verify `go build` works
- [ ] 15.2 Verify `go vet` passes
- [ ] 15.3 Verify `gofmt` formatting
- [ ] 15.4 Create release build script (optional)
