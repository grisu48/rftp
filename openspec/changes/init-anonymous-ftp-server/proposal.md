# Proposal: Initialize Anonymous Read-Only FTP Server

## Why
There is a need for a minimal, secure, read-only anonymous FTP server that:
- Serves files from a single directory without any write capabilities
- Drops privileges and chroots for defense-in-depth
- Supports both IPv4 and IPv6 (dual-stack)
- Has a minimal attack surface (no auth complexity, no TLS initially)
- Is easy to audit and maintain

Existing FTP servers (vsftpd, ProFTPD, Pure-FTPd) are feature-rich but complex. A minimal Go implementation reduces audit surface and is easier to secure.

## What Changes
- **NEW**: Complete FTP server implementation in Go
- **NEW**: YAML configuration file support
- **NEW**: Security hardening (chroot, read-only mount, privilege drop)
- **NEW**: Dual-stack IPv4/IPv6 listener
- **NEW**: Active and passive mode support (passive disabled by default)
- **NEW**: Read-only command set (USER, PASS, SYST, PWD, CWD, CDUP, TYPE, MODE, STRU, NOOP, QUIT, PASV, PORT, LIST, NLST, RETR, SIZE, MDTM, FEAT, OPTS, HELP)

## Impact
- New project with no existing code to modify
- Single external dependency (YAML library)
- Linux-focused (chroot and privilege dropping require Unix-like system)
