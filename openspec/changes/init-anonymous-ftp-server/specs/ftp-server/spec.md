# FTP Server Capability Specification

## ADDED Requirements

### Requirement: Anonymous-only authentication
The server SHALL accept only anonymous FTP connections using username "anonymous" or "ftp" with any password. The server MUST NOT support any other authentication mechanism.

#### Scenario: Anonymous login accepted
- **WHEN** a client sends `USER anonymous`
- **THEN** the server responds with `331 Anonymous login ok, send your complete email address as your password`

#### Scenario: FTP username accepted
- **WHEN** a client sends `USER ftp`
- **THEN** the server responds with `331 Anonymous login ok, send your complete email address as your password`

#### Scenario: Non-anonymous username rejected
- **WHEN** a client sends `USER` with any username other than "anonymous" or "ftp"
- **THEN** the server responds with `530 Anonymous access only` and closes the connection

#### Scenario: Any password accepted for anonymous
- **WHEN** a client sends `PASS` with any password after anonymous USER
- **THEN** the server responds with `230 Anonymous access granted`

---

### Requirement: Read-only file operations
The server SHALL only support read operations. The server MUST NOT support any command that modifies the filesystem.

#### Scenario: Write commands rejected
- **WHEN** a client sends any of: `STOR`, `APPE`, `STOU`, `DELE`, `RNFR`, `RNTO`, `MKD`, `RMD`, `SITE`
- **THEN** the server responds with `550 Read-only file system` and does not perform the operation

#### Scenario: File retrieval allowed
- **WHEN** a client sends `RETR <filename>` for a file within the served directory
- **THEN** the server transfers the file contents over the data connection

#### Scenario: Directory listing allowed
- **WHEN** a client sends `LIST` or `NLST`
- **THEN** the server returns a directory listing over the data connection

---

### Requirement: Single directory serving with chroot
The server SHALL serve files from a single configured directory. When running as root, the server MUST chroot into this directory before serving.

#### Scenario: Chroot on startup (when root)
- **WHEN** the server starts as root and `chroot: true` in config
- **THEN** the server chroots into the configured `serve_dir` before accepting connections

#### Scenario: Chroot failure is fatal
- **WHEN** chroot fails (e.g., directory doesn't exist, permission denied)
- **THEN** the server logs an error and exits with non-zero status

#### Scenario: Path traversal blocked
- **WHEN** a client attempts to access a path outside the chroot (e.g., `CWD ../../etc`)
- **THEN** the server responds with `550 Access denied` and does not change directory

---

### Requirement: Privilege dropping
The server MUST drop root privileges after binding to the port and performing chroot. The server SHALL run as the configured non-privileged user for all FTP operations.

#### Scenario: Privilege drop after binding
- **WHEN** the server starts as root
- **THEN** the server binds to the port, chroots, then drops to the configured user/group before accepting connections

#### Scenario: Privilege drop failure is fatal
- **WHEN** privilege dropping fails
- **THEN** the server logs an error and exits with non-zero status

#### Scenario: Running as non-root with root-only measures enabled
- **WHEN** the server starts as non-root while `chroot: true` or `read_only_mount: true` is configured
- **THEN** the server logs an error and exits with non-zero status, because a configured security measure cannot be applied

#### Scenario: Running as non-root with measures explicitly disabled
- **WHEN** the server starts as non-root with `chroot: false` and `read_only_mount: false`
- **THEN** the server logs that it is already unprivileged (no root privileges exist to drop) and continues serving

---

### Requirement: Read-only filesystem mount
When `read_only_mount: true` is configured, the server SHALL re-mount the served directory as read-only before dropping privileges. If the re-mount fails, the server MUST exit with non-zero status (secure by default).

#### Scenario: Read-only mount attempted
- **WHEN** the server starts as root and `read_only_mount: true` in config
- **THEN** the server attempts to re-mount the served directory with read-only flag

#### Scenario: Read-only mount failure is fatal
- **WHEN** the server starts as root, `read_only_mount: true` is configured, and the read-only re-mount fails
- **THEN** the server logs an error and exits with non-zero status

---

### Requirement: Secure by default (fail-closed security hardening)
The server SHALL apply every configured security measure or fail. The server MUST NOT skip or silently ignore a configured security measure, and MUST NOT serve as root.

#### Scenario: Configured measure cannot be applied
- **WHEN** any configured security measure cannot be applied (chroot fails, read-only re-mount fails, or privilege drop fails)
- **THEN** the server logs an error and exits with non-zero status

#### Scenario: Privilege dropping is never skipped when running as root
- **WHEN** the server starts as root
- **THEN** the server drops privileges to the configured user/group before serving any connection, and exits with non-zero status if the drop fails or is not performed

#### Scenario: Root-only measures enabled without root
- **WHEN** the server starts as non-root with `chroot: true` or `read_only_mount: true` configured
- **THEN** the server refuses to start and exits with non-zero status

#### Scenario: Unprivileged start with measures explicitly disabled
- **WHEN** the server starts as non-root with `chroot: false` and `read_only_mount: false`
- **THEN** the server logs that it is already unprivileged and continues serving (no root privileges exist to drop)

---

### Requirement: Dual-stack IPv4/IPv6 support
The server MUST listen on both IPv4 and IPv6 using a dual-stack socket.

#### Scenario: Dual-stack listener
- **WHEN** the server starts with listen address `::` or `:21`
- **THEN** the server accepts connections on both IPv4 and IPv6

#### Scenario: IPv4 connection
- **WHEN** a client connects via IPv4
- **THEN** the server handles the connection normally

#### Scenario: IPv6 connection
- **WHEN** a client connects via IPv6
- **THEN** the server handles the connection normally

---

### Requirement: Passive mode disabled by default
Passive FTP mode (`PASV`/`EPSV`) SHALL be disabled by default and MUST be explicitly enabled via configuration.

#### Scenario: Passive mode disabled
- **WHEN** `passive_enabled: false` (default) in config
- **THEN** the server responds to `PASV` and `EPSV` with `502 Passive mode disabled`

#### Scenario: Passive mode enabled
- **WHEN** `passive_enabled: true` in config
- **THEN** the server responds to `PASV`/`EPSV` with a valid passive address and port

---

### Requirement: Active mode support
The server MUST support active mode (`PORT`/`EPRT`) for data transfers.

#### Scenario: IPv4 active mode
- **WHEN** a client sends `PORT h1,h2,h3,h4,p1,p2`
- **THEN** the server connects to the specified address for data transfer

#### Scenario: IPv6 active mode
- **WHEN** a client sends `EPRT |2|IPv6-address|port|`
- **THEN** the server connects to the specified IPv6 address for data transfer

---

### Requirement: YAML configuration file
The server MUST accept a single YAML configuration file as a command-line argument.

#### Scenario: Config file provided
- **WHEN** the server is started with `-config /path/to/config.yaml`
- **THEN** the server loads configuration from the specified file

#### Scenario: Config file missing
- **WHEN** the specified config file does not exist or is unreadable
- **THEN** the server logs an error and exits with non-zero status

#### Scenario: Invalid YAML
- **WHEN** the config file contains invalid YAML
- **THEN** the server logs an error and exits with non-zero status

#### Scenario: Missing required config
- **WHEN** required config fields are missing
- **THEN** the server logs an error indicating which fields are missing and exits

---

### Requirement: Logging to stdout/stderr only
The server MUST log only to stdout (info/debug) and stderr (warn/error). The server MUST NOT write log files.

#### Scenario: Info logs to stdout
- **WHEN** the server logs informational messages (startup, connections)
- **THEN** the output goes to stdout

#### Scenario: Error logs to stderr
- **WHEN** the server logs warnings or errors
- **THEN** the output goes to stderr

---

### Requirement: Plain FTP only (no TLS)
The server SHALL only support plain FTP (no TLS/FTPS). TLS support may be added in a future version.

#### Scenario: AUTH TLS rejected
- **WHEN** a client sends `AUTH TLS` or `AUTH SSL`
- **THEN** the server responds with `502 TLS not supported`

#### Scenario: PROT command rejected
- **WHEN** a client sends `PROT P`
- **THEN** the server responds with `502 TLS not supported`

---

### Requirement: Minimal external dependencies
The server MUST NOT use external dependencies except for YAML parsing.

#### Scenario: Dependency audit
- **WHEN** reviewing `go.mod`
- **THEN** only the YAML library (and its dependencies) appear as external requirements

---

### Requirement: Graceful shutdown
The server MUST handle SIGTERM and SIGINT gracefully, closing all active connections.

#### Scenario: SIGTERM received
- **WHEN** the server receives SIGTERM
- **THEN** the server stops accepting new connections, closes existing connections gracefully, and exits with status 0

#### Scenario: SIGINT received
- **WHEN** the server receives SIGINT (Ctrl+C)
- **THEN** the server stops accepting new connections, closes existing connections gracefully, and exits with status 0
