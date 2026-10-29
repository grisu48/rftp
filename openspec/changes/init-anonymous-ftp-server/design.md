# Design: Anonymous Read-Only FTP Server

## Context
Building a minimal, secure FTP server in Go that serves a single directory anonymously over plain FTP. The server must be secure by default with privilege dropping and chroot.

## Goals / Non-Goals

### Goals
- Serve files read-only from a single directory
- Accept only anonymous connections
- Drop privileges after binding
- Chroot into served directory when possible
- Support dual-stack IPv4/IPv6
- Minimal codebase and dependencies
- Plain FTP only (TLS may be added later)

### Non-Goals
- User authentication (only anonymous)
- Write operations (upload, delete, rename, mkdir)
- TLS/FTPS support (future consideration)
- Virtual users or multiple directories
- FTP extensions beyond basic read operations

## Decisions

### Decision: Use Go standard library for FTP protocol
**What**: Implement FTP protocol handling using only Go standard library (`net`, `bufio`, `os`, `path/filepath`, etc.)

**Why**:
- Minimizes external dependencies
- Full control over security-sensitive code
- Standard library is well-audited

**Alternatives considered**:
- Using an existing FTP library (e.g., `github.com/jlaffaye/ftp`) — rejected due to dependency and potential unwanted features

### Decision: Single YAML configuration file
**What**: All configuration via a single YAML file passed as command-line argument

**Why**:
- Simple deployment model
- Easy to audit configuration
- No environment variable sprawl

**Configuration structure**:
```yaml
# Server settings
listen_addr: ":21"          # Listen address (dual-stack by default)
passive_enabled: false      # Passive mode disabled by default
passive_port_min: 40000     # Passive port range (if enabled)
passive_port_max: 40100

# Security settings
serve_dir: /srv/ftp         # Directory to serve (will be chrooted)
user: nobody                # Optional: user to drop privileges to (default: nobody)
group: nogroup              # Optional: group to drop privileges to (default: nogroup)
chroot: true                # Chroot into serve_dir (requires root)
read_only_mount: true       # Re-mount serve_dir as read-only

# Logging
log_level: info             # debug, info, warn, error
```

Only `listen_addr` and `serve_dir` are required. `user` and `group` are
**optional**: when omitted (or set to an empty value) they default to
`nobody`/`nogroup`, which is the privilege drop target used when the server
runs as root.

### Decision: Privilege dropping and chroot sequence
**What**: When running as root, perform security hardening in this order:
1. Bind to port (requires root for ports < 1024)
2. Chroot into the served directory (if enabled)
3. Re-mount the directory as read-only (if enabled)
4. Drop privileges to configured user/group
5. Continue serving

The sequence is **fail-closed**: every step that is enabled in configuration
must succeed. If any step fails, the server exits with a non-zero status — it
never continues serving in a degraded security posture (see *Secure by default*).

**Why**:
- Binding must happen before dropping privileges
- Chroot before dropping privileges ensures we're in the right context
- Read-only mount prevents any accidental writes
- Dropping privileges last minimizes root exposure
- Fail-closed hardening makes the security guarantee explicit and auditable

**Alternatives considered**:
- Dropping privileges before chroot — rejected, as chroot typically requires root
- Warn-and-continue when a hardening step fails — rejected, see *Secure by default*

### Decision: Secure by default (fail-closed security hardening)
**What**: The server MUST apply every configured security measure or fail:
- `chroot: true` (default): chroot into `serve_dir`; if chroot fails, **exit with non-zero status**
- `read_only_mount: true` (default): re-mount `serve_dir` read-only; if the re-mount fails, **exit with non-zero status**
- Privilege dropping: when the server starts as root it MUST drop privileges before serving — to the configured `user`/`group`, or to the default `nobody`/`nogroup` when they are not configured (`user` and `group` are both optional); if the drop fails, **exit with non-zero status**
- Starting as non-root while `chroot: true` or `read_only_mount: true` is configured: the measure cannot be applied, so the server **refuses to start** (exit non-zero). The operator must either start as root or explicitly set the measure to `false`.
- Starting as non-root with `chroot: false` and `read_only_mount: false`: the process is already unprivileged, so there are no root privileges to drop — the privilege-drop goal is satisfied. The server logs this explicitly (it is not a silent skip) and continues.

In all cases the server MUST NOT serve as root. Skipping or silently ignoring
a configured security measure is not permitted.

**Why**:
- Warn-and-continue silently degrades the security posture; an operator may never notice the warning
- Fail-closed turns a degraded configuration into a visible, auditable startup error
- Making the unprivileged path explicit (opt-out via config) keeps `chroot: true` / `read_only_mount: true` meaningful as defaults

**Alternatives considered**:
- Warn and continue if the read-only mount fails — rejected: silently ignores a configured security measure
- Allow starting as non-root with `chroot`/`read_only_mount` enabled — rejected: the configured measures would be skipped
- Refuse to start as non-root under any circumstances — rejected: running unprivileged is safe (no root privileges exist to drop), and containers commonly run services as non-root users with the root-only measures explicitly disabled

### Decision: Read-only command whitelist
**What**: Only implement FTP commands that are read-only:
- Connection: `USER`, `PASS`, `QUIT`, `NOOP`
- Navigation: `PWD`, `CWD`, `CDUP`, `TYPE`, `MODE`, `STRU`
- Information: `SYST`, `FEAT`, `HELP`, `SITE` (limited)
- Listing: `LIST`, `NLST`, `MLSD` (if needed)
- Retrieval: `RETR`, `SIZE`, `MDTM`
- Passive/Active: `PASV`, `PORT`, `EPSV`, `EPRT` (dual-stack)

**Explicitly rejected commands** (write operations):
- `STOR`, `APPE`, `STOU` (upload)
- `DELE` (delete)
- `RNFR`, `RNTO` (rename)
- `MKD`, `RMD` (make/remove directory)
- `SITE` (site-specific commands)

### Decision: Dual-stack IPv6/IPv4 support
**What**: Listen on both IPv4 and IPv6 using a dual-stack socket (`tcp` network with `::` address)

**Why**:
- Modern requirement for network services
- Single socket handles both protocols
- Use `EPSV`/`EPRT` for IPv6 passive/active mode

### Decision: Passive mode disabled by default
**What**: Passive mode (`PASV`/`EPSV`) is disabled unless explicitly enabled in config

**Why**:
- Passive mode requires opening additional ports (firewall complexity)
- Many deployments use active mode or have firewall rules for passive ranges
- Security principle: minimize open ports by default

### Decision: Logging to stdout/stderr only
**What**: All logging goes to stdout (info/debug) and stderr (warnings/errors)

**Why**:
- Simple deployment (container-friendly)
- No file permission issues after privilege drop
- Standard Unix philosophy

**Log format**: Structured or simple key-value pairs with timestamp

### Decision: Directory structure
```
/
└── cmd/rftp/
    ├── main.go             # Entry point, flag parsing
    ├── config/
    │   └── config.go       # YAML config parsing
    ├── logger/
    │   └── logger.go       # Leveled logging (stdout/stderr)
    ├── server/
    │   ├── server.go       # FTP server lifecycle
    │   ├── listener.go     # TCP listener (dual-stack)
    │   ├── session.go      # Per-connection session handling
    │   ├── commands.go     # FTP command handlers
    │   └── passive.go      # Passive mode port management
    ├── security/
    │   ├── privileges.go   # Privilege dropping
    │   ├── chroot.go       # Chroot handling
    │   └── mount.go        # Read-only mount
    └── ftp/
        ├── protocol.go     # FTP protocol constants and helpers
        └── types.go        # Data structures
```

## Risks / Trade-offs

### Risk: Chroot requires root
**Mitigation**: If `chroot` is enabled and the server is not running as root, it refuses to start with a clear error (secure by default). When running as root, a chroot failure is fatal.

### Risk: Read-only mount may not be possible in all environments
**Mitigation**: Fail closed — if `read_only_mount` is enabled and the re-mount fails, the server exits with a non-zero status. Operators in restricted environments must explicitly set `read_only_mount: false`, which is a visible, auditable configuration choice rather than a silent skip.

### Risk: Passive mode port range exhaustion
**Mitigation**: Implement port range rotation; close idle passive connections

### Trade-off: Plain FTP sends credentials in cleartext
**Mitigation**: This is anonymous FTP, so no real credentials; document that TLS may be added later

## Migration Plan
Not applicable — new project.

## Open Questions
- Should we support `MLSD`/`MLST` (machine-readable listings)? → Start with `LIST`/`NLST` only
- Should passive mode use a specific external IP for NAT scenarios? → Add `passive_addr` config option if needed
- What should happen if privilege drop fails? → Fail fast and exit (security requirement)
