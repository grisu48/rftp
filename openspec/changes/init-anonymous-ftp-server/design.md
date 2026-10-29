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
user: nobody                # User to drop privileges to
group: nogroup              # Group to drop privileges to
chroot: true                # Chroot into serve_dir (requires root)
read_only_mount: true       # Re-mount serve_dir as read-only

# Logging
log_level: info             # debug, info, warn, error
```

### Decision: Privilege dropping and chroot sequence
**What**: When running as root, perform security hardening in this order:
1. Bind to port (requires root for ports < 1024)
2. Chroot into the served directory
3. Re-mount the directory as read-only (if possible)
4. Drop privileges to configured user/group
5. Continue serving

**Why**:
- Binding must happen before dropping privileges
- Chroot before dropping privileges ensures we're in the right context
- Read-only mount prevents any accidental writes
- Dropping privileges last minimizes root exposure

**Alternatives considered**:
- Dropping privileges before chroot — rejected, as chroot typically requires root

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
├── main.go                 # Entry point, flag parsing
├── config/
│   └── config.go           # YAML config parsing
├── server/
│   ├── server.go           # FTP server lifecycle
│   ├── listener.go         # TCP listener (dual-stack)
│   ├── session.go          # Per-connection session handling
│   ├── commands.go         # FTP command handlers
│   └── passive.go          # Passive mode port management
├── security/
│   ├── privileges.go       # Privilege dropping
│   ├── chroot.go           # Chroot handling
│   └── mount.go            # Read-only mount
└── ftp/
    ├── protocol.go         # FTP protocol constants and helpers
    └── types.go            # Data structures
```

## Risks / Trade-offs

### Risk: Chroot requires root
**Mitigation**: Document that chroot requires running as root initially; provide clear error messages if chroot fails

### Risk: Read-only mount may not be possible in all environments
**Mitigation**: Make read-only mount configurable; warn if it fails but continue if chroot succeeded

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
