# Implementation Tasks

## 1. Project Setup
- [x] 1.1 Initialize Go module (`go mod init`)
- [x] 1.2 Add YAML dependency (`gopkg.in/yaml.v3`)
- [x] 1.3 Create directory structure
- [x] 1.4 Add `.gitignore` (binary, config examples)
- [x] 1.5 Create `main.go` with basic flag parsing

## 2. Configuration
- [x] 2.1 Define config struct with YAML tags
- [x] 2.2 Implement config file loading and validation
- [x] 2.3 Add config defaults (passive disabled, sensible ports)
- [x] 2.4 Validate serve directory exists and is readable
- [x] 2.5 Add unit tests for config parsing
- [x] 2.6 Make `user`/`group` optional (default `nobody`/`nogroup` when unset)

## 3. Security Layer
- [x] 3.1 Implement chroot functionality (`security/chroot.go`)
- [x] 3.2 Implement privilege dropping (`security/privileges.go`)
- [x] 3.3 Implement read-only mount (`security/mount.go`)
- [x] 3.4 Create security initialization sequence (bind → chroot → mount → drop)
- [x] 3.5 Add tests for privilege dropping (requires root, may need integration test)
- [x] 3.6 Add tests for chroot behavior
- [x] 3.7 Enforce secure-by-default (fail-closed): configured security measures must be applied or the program exits (`cmd/rftp/security/harden.go`)

## 4. FTP Server Core
- [x] 4.1 Create TCP listener with dual-stack support (`server/listener.go`)
- [x] 4.2 Implement connection accept loop (`server/server.go`)
- [x] 4.3 Create session structure for per-connection state (`server/session.go`)
- [x] 4.4 Implement FTP command parser (line-based, CRLF handling)
- [x] 4.5 Implement response writer (standard FTP response codes)

## 5. FTP Commands - Connection & Auth
- [x] 5.1 Implement `USER` command (accept only "anonymous" or "ftp")
- [x] 5.2 Implement `PASS` command (accept any password for anonymous)
- [x] 5.3 Implement `QUIT` command
- [x] 5.4 Implement `NOOP` command
- [x] 5.5 Implement login state machine (require USER before PASS, etc.)

## 6. FTP Commands - Navigation
- [x] 6.1 Implement `PWD` command
- [x] 6.2 Implement `CWD` command (with path sanitization)
- [x] 6.3 Implement `CDUP` command
- [x] 6.4 Implement `TYPE` command (ASCII/Image)
- [x] 6.5 Implement `MODE` and `STRU` commands (accept and ignore)

## 7. FTP Commands - Information
- [x] 7.1 Implement `SYST` command
- [x] 7.2 Implement `FEAT` command (advertise supported features)
- [x] 7.3 Implement `HELP` command
- [x] 7.4 Implement `SIZE` command
- [x] 7.5 Implement `MDTM` command

## 8. FTP Commands - Listing & Retrieval
- [x] 8.1 Implement `LIST` command (Unix-style listing)
- [x] 8.2 Implement `NLST` command (name list)
- [x] 8.3 Implement `RETR` command (file retrieval)
- [x] 8.4 Add path traversal protection (prevent `../` escapes)
- [x] 8.5 Add symlink handling policy (follow or reject?)

## 9. Data Transfer - Active Mode
- [x] 9.1 Implement `PORT` command (IPv4 active mode)
- [x] 9.2 Implement `EPRT` command (extended active mode, IPv6-capable)
- [x] 9.3 Implement active data connection establishment

## 10. Data Transfer - Passive Mode (Optional)
- [x] 10.1 Implement passive port range management (`server/passive.go`)
- [x] 10.2 Implement `PASV` command (IPv4 passive mode)
- [x] 10.3 Implement `EPSV` command (extended passive mode, IPv6-capable)
- [x] 10.4 Implement passive listener lifecycle
- [x] 10.5 Add passive mode enable/disable based on config

## 11. Logging
- [x] 11.1 Implement structured logger (stdout/stderr)
- [x] 11.2 Add connection logging (connect, disconnect, commands)
- [x] 11.3 Add error logging with context
- [x] 11.4 Add security event logging (auth attempts, path violations)

## 12. Signal Handling & Lifecycle
- [x] 12.1 Implement graceful shutdown on SIGTERM/SIGINT
- [x] 12.2 Close all active connections on shutdown
- [x] 12.3 Add startup logging (config summary, security status)

## 13. Testing
- [x] 13.1 Unit tests for config parsing
- [x] 13.2 Unit tests for path sanitization
- [x] 13.3 Unit tests for FTP command parsing
- [x] 13.4 Integration test: basic anonymous login
- [x] 13.5 Integration test: file retrieval
- [x] 13.6 Integration test: directory listing
- [x] 13.7 Integration test: passive mode (when enabled)
- [x] 13.8 Integration test: IPv6 connectivity
- [x] 13.9 Security test: verify write commands are rejected
- [x] 13.10 Security test: verify path traversal is blocked

## 14. Documentation
- [x] 14.1 Create `README.md` with usage instructions
- [x] 14.2 Create example config file (`config.example.yaml`)
- [x] 14.3 Document security model (chroot, privilege drop, read-only)
- [x] 14.4 Document IPv4/IPv6 setup
- [x] 14.5 Add deployment notes (systemd unit example)

## 15. Build & Distribution
- [x] 15.1 Verify `go build` works
- [x] 15.2 Verify `go vet` passes
- [x] 15.3 Verify `gofmt` formatting
- [x] 15.4 Create release build script (optional)
