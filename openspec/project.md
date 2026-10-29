# Project Context

## Purpose
A minimal, security-focused, read-only anonymous FTP server written in Go. The server serves a single directory over plain FTP (no TLS initially) with dual-stack IPv4/IPv6 support.

## Tech Stack
- **Language**: Go (standard library only)
- **Configuration**: YAML (single external dependency: `gopkg.in/yaml.v3` or similar)
- **Target Platforms**: Linux (primary), with privilege dropping and chroot support

## Project Conventions

### Code Style
- Follow standard Go conventions (`gofmt`, `go vet`)
- Minimal dependencies — standard library preferred
- Security-first: all file operations must be validated and sandboxed

### Architecture
- Single binary, single configuration file
- Clear separation: config parsing, server lifecycle, FTP protocol handler, security (privilege drop, chroot)
- No plugin system, no extensibility beyond configuration

### Security Requirements
- **MUST** drop privileges after binding to port
- **MUST** chroot into the served directory when running as root
- **MUST** re-mount the served directory as read-only when configured
- **MUST** reject all authentication except anonymous
- **MUST** only allow read operations (no upload, delete, rename, mkdir, etc.)
- **Secure by default (fail-closed)**: every configured security measure (chroot, read-only mount, privilege drop) MUST be applied or the program MUST fail; skipping or silently ignoring a configured security measure is not permitted, and the program MUST NOT serve as root

### Testing Strategy
- Unit tests for config parsing and path validation
- Integration tests for FTP protocol compliance
- Security tests for privilege dropping and chroot behavior

## Domain Context
- FTP protocol: RFC 959 (base), RFC 2428 (IPv6 extensions), RFC 2640 (UTF-8)
- Passive mode: RFC 959 Section 4.2.2 (PORT/PASV commands)
- Anonymous FTP: standard "anonymous" or "ftp" username with email-like password

## Important Constraints
- **Read-only**: No write operations whatsoever (no STOR, DELE, RNFR/RNTO, MKD, RMD, APPE, SITE)
- **Anonymous only**: No user authentication, no PAM, no password files
- **Single directory**: One root directory served, no virtual hosts or multi-tenant
- **Minimal**: Small codebase, no unnecessary features
- **Plain FTP only**: No FTPS/TLS in initial version (may be added later)

## External Dependencies
- YAML parsing library only (e.g., `gopkg.in/yaml.v3`)
- All other functionality uses Go standard library
