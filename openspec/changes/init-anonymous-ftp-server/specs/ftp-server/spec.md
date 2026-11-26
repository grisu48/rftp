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
The server SHALL serve files from a single configured directory. When running as root, the server MUST chroot into this directory before serving. Because `chroot(2)` is per-thread, the chroot MUST be applied before a startup re-exec of the process image, so that the whole process (all threads) is chrooted.

#### Scenario: Chroot on startup (when root)
- **WHEN** the server starts as root and `chroot: true` in config
- **THEN** the server chroots into the configured `serve_dir` before accepting connections, and every thread of the process sees the chrooted root

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

#### Scenario: Privilege drop target defaults when user/group are not configured
- **WHEN** the server starts as root without `user` or `group` configured (both are optional)
- **THEN** the server drops privileges to the predefined default uid/gid 65534/65534 before serving, and exits with non-zero status if the drop fails

#### Scenario: Privilege drop targets given as names
- **WHEN** `user` and/or `group` are configured as names (e.g. `user: nobody`, `group: nogroup`)
- **THEN** the server resolves them via the user/group database and drops privileges to the resolved uid/gid; an unresolvable name is a fatal error (non-zero exit)

#### Scenario: Privilege drop targets given as numeric IDs
- **WHEN** `user` and/or `group` are configured as numeric IDs (e.g. `user: "65534"`)
- **THEN** the server drops privileges to that numeric uid/gid directly, without requiring a user/group database

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

### Requirement: Read-only filesystem mount in a private mount namespace
When `read_only_mount: true` is configured, the server SHALL re-mount the served directory as read-only inside its own private mount namespace (`unshare(CLONE_NEWNS)` + making the mount tree private), so that the rest of the system is not affected. The namespace is entered before a startup re-exec of the process image (because `unshare(2)` is per-thread), so the read-only view applies to the whole server process. If the namespace cannot be entered or the re-mount fails, the server MUST exit with non-zero status (secure by default).

#### Scenario: Read-only mount attempted in a private namespace
- **WHEN** the server starts as root and `read_only_mount: true` in config
- **THEN** the server enters a private mount namespace and re-mounts the served directory with the read-only flag inside it

#### Scenario: Read-only mount failure is fatal
- **WHEN** the server starts as root, `read_only_mount: true` is configured, and entering the private mount namespace or the read-only re-mount fails
- **THEN** the server logs an error and exits with non-zero status

#### Scenario: Host mount namespace unaffected
- **WHEN** the server starts as root with `read_only_mount: true` and has re-mounted the served directory read-only in its private mount namespace
- **THEN** other processes on the system can still write to the served directory (the read-only re-mount is visible only inside the server's mount namespace)

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

### Requirement: Passive mode enabled by default
Passive FTP mode (`PASV`/`EPSV`) SHALL be enabled by default and MUST be possible to disable via configuration.

#### Scenario: Passive mode enabled (default)
- **WHEN** `passive_enabled` is not set (default `true`) in config
- **THEN** the server responds to `PASV`/`EPSV` with a valid passive address and port

#### Scenario: Passive mode disabled
- **WHEN** `passive_enabled: false` in config
- **THEN** the server responds to `PASV` and `EPSV` with `502 Passive mode disabled`

---

### Requirement: Per-connection bandwidth limit
The server MUST support an optional `bandwidth_limit` configuration value capping the rate of each connection in bytes per second. The value may be a bare number (bytes per second) or a human-readable string with a unit suffix (e.g. `512KiB/s`, `10MB/s`; decimal units KB/MB/GB/TB, binary units KiB/MiB/GiB/TiB, case-insensitive, optional `/s`). `0` or unset SHALL mean unlimited (the default). When set, every connection (control and data) SHALL be limited individually by a token bucket (initial burst of one second worth allowed); the limit is per connection and MUST NOT be shared across connections. Invalid values (negative, non-numeric, unknown unit, overflow) SHALL be rejected at startup.

#### Scenario: Unlimited by default
- **WHEN** no `bandwidth_limit` is configured (or it is `0`)
- **THEN** connections are not rate-limited

#### Scenario: Human-readable limit accepted
- **WHEN** `bandwidth_limit: "10MiB/s"` is configured
- **THEN** the limit is 10485760 bytes per second applied to each connection

#### Scenario: Invalid limit rejected
- **WHEN** `bandwidth_limit` is negative, non-numeric, has an unknown unit or overflows
- **THEN** the server logs an error and exits with a non-zero status

#### Scenario: Data transfer throttled per connection
- **WHEN** `bandwidth_limit` is set and a client downloads a file over a data connection
- **THEN** the transfer rate of that connection does not exceed the configured limit (beyond the initial one-second burst)

---

### Requirement: Active mode support
The server MUST support active mode (`PORT`/`EPRT`) for data transfers.

#### Scenario: IPv4 active mode
- **WHEN** a client sends `PORT h1,h2,h3,h4,p1,p2`
- **THEN** the server connects to the specified address for data transfer

#### Scenario: IPv6 active mode
- **WHEN** a client sends `EPRT |2|IPv6-address|port|`
- **THEN** the server connects to the specified IPv6 address for data transfer

#### Scenario: Long-address active mode (LPRT)
- **WHEN** a client sends `LPRT <af>,<hal>,<address bytes>,<pal>,<port bytes>` (RFC 1639)
- **THEN** the server responds with `200 LPRT command successful` and connects to the specified address for data transfer

#### Scenario: Active mode behind a port forward/NAT
- **WHEN** the server runs behind a port forward (e.g. `podman run -p 2121:2121`), so the control connection arrives from the forwarder's address, and the client sends `PORT`/`EPRT`/`LPRT` advertising its own **loopback** address
- **THEN** the server responds `200` and connects to the advertised loopback address, so active mode works through the port forward

#### Scenario: Anti FTP-bounce (CWE-441)
- **WHEN** a client sends `PORT`/`EPRT`/`LPRT` with a foreign **non-loopback** address that is not the control connection's peer
- **THEN** the server responds `501 ... must match the control connection` and does NOT connect to that address

---

### Requirement: Recognized but unimplemented commands get 502
Commands that are recognized but not implemented (`LPSV`, `STAT`, `ABOR`, `ALLO`, `ACCT`, `SMNT`, `REIN`, `MLSD`, `MLST`, `REST`) SHALL be answered with `502 Command not implemented`, so that clients fall back to supported commands. A completely unknown command SHALL be answered with `500 Command not recognized`.

#### Scenario: Passive fallback command not implemented
- **WHEN** a client sends `LPSV` (e.g. after `EPSV`/`PASV` were refused because passive mode is disabled via configuration)
- **THEN** the server responds with `502 Command not implemented`

#### Scenario: Unknown command
- **WHEN** a client sends a command the server does not recognize at all
- **THEN** the server responds with `500 Command not recognized`

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
- **WHEN** required config fields (`listen_addr`, `serve_dir`) are missing from all configuration sources (config file and environment variables)
- **THEN** the server logs an error indicating which fields are missing and exits

#### Scenario: Optional user/group omitted
- **WHEN** `user` and `group` are omitted (or explicitly set to an empty value) in the config file
- **THEN** the server accepts the configuration and uses the predefined default uid/gid 65534/65534 as the privilege drop target

---

### Requirement: Configuration via environment variables, config file takes precedence
The server SHALL accept configuration from environment variables in addition to the YAML configuration file. Each configuration key maps to an environment variable named `RFTP_` followed by the uppercased key (e.g. `listen_addr` → `RFTP_LISTEN_ADDR`, `bandwidth_limit` → `RFTP_BANDWIDTH_LIMIT`), parsed with the same rules and accepting the same values as the corresponding config file field. The `-config` flag SHALL be optional: when omitted, configuration is taken from environment variables alone. The config file SHALL take precedence over environment variables on a per-key basis: for any key set in both, the config file value SHALL be used, and environment variables SHALL only supply values for keys not present in the config file. Invalid environment variable values SHALL be rejected at startup with a non-zero exit status, exactly like invalid config file values.

#### Scenario: Configuration from environment variables only
- **WHEN** the server is started without `-config` and the required fields are provided via environment variables (e.g. `RFTP_LISTEN_ADDR=:21`, `RFTP_SERVE_DIR=/srv/ftp`)
- **THEN** the server starts using the environment-provided configuration

#### Scenario: Config file takes precedence over environment variables
- **WHEN** a key is set both in the config file and as an environment variable (e.g. `passive_enabled: true` in the file and `RFTP_PASSIVE_ENABLED=false` in the environment)
- **THEN** the config file value (`true`) is used and the environment variable is ignored for that key

#### Scenario: Environment variables complement the config file
- **WHEN** the server is started with `-config` and environment variables are set for keys that are not present in the config file
- **THEN** those keys take their values from the environment variables

#### Scenario: Invalid environment variable value rejected
- **WHEN** an `RFTP_*` environment variable holds a value that is invalid for its key (e.g. `RFTP_BANDWIDTH_LIMIT=fast`)
- **THEN** the server logs an error and exits with non-zero status

#### Scenario: Required fields missing from all sources
- **WHEN** `listen_addr` and `serve_dir` are provided neither in the config file nor via environment variables
- **THEN** the server logs an error indicating which fields are missing and exits with non-zero status

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
