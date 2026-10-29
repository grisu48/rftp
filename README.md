# rftp

**Note: This project is an experiment. This software is probably not safe. Do not  use it.**

A minimal, security-focused, **read-only anonymous FTP server** written in Go.
It serves a single directory over plain FTP (no TLS) with dual-stack IPv4/IPv6
support, and hardens itself at startup by chrooting into the served directory,
re-mounting it read-only, and dropping root privileges.

## Features

- **Anonymous only** — accepts `anonymous` or `ftp` with any password; all other
  user names are rejected and the connection is closed.
- **Read-only** — only read operations are implemented. Upload, delete, rename
  and directory creation (`STOR`, `APPE`, `STOU`, `DELE`, `RNFR`, `RNTO`,
  `MKD`, `RMD`, `SITE`) are rejected with `550 Read-only file system`.
- **Single directory** — one root directory is served; path traversal above the
  root (`CWD ../../etc`) and symlinks pointing outside the root are blocked with
  `550 Access denied`.
- **Dual-stack** — listens on both IPv4 and IPv6 via a single dual-stack socket.
- **Active and passive mode** — `PORT`/`EPRT` (active) always supported;
  `PASV`/`EPSV` (passive) disabled by default, enable via configuration.
- **Security hardening** — when started as root: bind → chroot → read-only
  re-mount → drop privileges to a non-privileged user. Privilege drop failure
  is fatal.
- **Plain FTP only** — `AUTH TLS`/`PROT` are rejected with `502 TLS not supported`.
- **Minimal dependencies** — Go standard library plus `gopkg.in/yaml.v3` only.

## Supported commands

| Category     | Commands                                                        |
|--------------|-----------------------------------------------------------------|
| Connection   | `USER`, `PASS`, `QUIT`, `NOOP`                                   |
| Navigation   | `PWD`, `CWD`, `CDUP`, `TYPE`, `MODE`, `STRU`                     |
| Information  | `SYST`, `FEAT`, `HELP`, `SIZE`, `MDTM`, `OPTS UTF8 ON`           |
| Transfers    | `LIST`, `NLST`, `RETR`                                           |
| Data setup   | `PORT`, `EPRT`, `PASV`, `EPSV` (passive only when enabled)       |

## Project layout

```text
cmd/rftp/
├── main.go            # Entry point: flag parsing, hardening sequence, signals
├── config/            # YAML config parsing and validation
├── ftp/               # FTP protocol constants, command parser, types
├── logger/            # Leveled logging (info/debug→stdout, warn/error→stderr)
├── security/          # Privilege drop, chroot, read-only mount (Linux)
└── server/            # Listener, server lifecycle, sessions, commands, passive ports
```

## Building

```sh
go build -o rftp ./cmd/rftp
go vet ./...
go test ./...
```

## Running

```sh
sudo ./rftp -config config.example.yaml
```

Running as root is recommended: it enables chroot, the read-only re-mount and
privilege dropping. The server is **secure by default (fail-closed)**: every
configured security measure must be applied or the program exits with a
non-zero status. In particular, when started as a non-root user with `chroot`
or `read_only_mount` enabled (the defaults), it refuses to start — set them to
`false` explicitly to run without root.

### Configuration

All configuration lives in a single YAML file (see
[`config.example.yaml`](config.example.yaml)):

```yaml
listen_addr: ":21"          # dual-stack IPv4/IPv6
passive_enabled: false      # PASV/EPSV disabled by default
passive_port_min: 40000
passive_port_max: 40100

serve_dir: /srv/ftp         # directory to serve (chrooted when root)
user: nobody                # optional: privilege drop target (default: nobody)
group: nogroup              # optional: privilege drop target (default: nogroup)
chroot: true
read_only_mount: true

log_level: info             # debug, info, warn, error
```

Only `listen_addr` and `serve_dir` are required. `user` and `group` are
**optional**: when omitted (or empty) they default to `nobody`/`nogroup`. The
server still never serves as root — when started as root it always drops
privileges (to the configured or default target) or exits.

- Info/debug logs go to **stdout**, warnings/errors go to **stderr**. No log
  files are written.
- A missing/unreadable config file, invalid YAML, or missing required fields
  (`listen_addr`, `serve_dir`) cause the server to log an error and exit with a
  non-zero status.
- `SIGTERM`/`SIGINT` trigger a graceful shutdown: the listener is closed and all
  active connections are closed before exiting with status 0.

## Security model

1. Bind the control port (needs root for ports < 1024).
2. `chroot` into `serve_dir` (fatal on failure when enabled).
3. Re-mount `serve_dir` read-only (fatal on failure when enabled).
4. Drop privileges to `user`/`group` (fatal on failure).
5. Serve read-only, validating every path and rejecting symlink escapes.

**Secure by default (fail-closed):** the server never skips or silently ignores
a configured security measure. If chroot, the read-only re-mount or the
privilege drop fails, the program logs an error and exits with a non-zero
status. The server **never serves as root**: when started as root it always
drops privileges before serving; when started unprivileged with `chroot` or
`read_only_mount` enabled it refuses to start (set them to `false` explicitly
to run without root — the process is then already unprivileged, so there are
no root privileges to drop).

Regardless of privileges, the server refuses all write commands and blocks
path traversal, so the served directory is never modified.

## Deployment (systemd)

```ini
[Unit]
Description=rftp - read-only anonymous FTP server
After=network.target

[Service]
ExecStart=/usr/local/bin/rftp -config /etc/rftp/config.yaml
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_CHROOT
NoNewPrivileges=true
ProtectSystem=strict
ReadOnlyPaths=/srv/ftp

[Install]
WantedBy=multi-user.target
```

## Container image

A `Containerfile` builds a minimal image: a **scratch** runtime stage that
contains only the `rftp` binary, a default configuration, and default content.
The build stage uses `registry.opensuse.org/opensuse/bci/golang`.

| Path in container | Purpose                                                        |
|-------------------|----------------------------------------------------------------|
| `/rftp`           | the rftp binary — the image **entrypoint**                     |
| `/conf/rftp.yaml` | configuration file (a minimal default is provided; mount yours) |
| `/ftp`            | served FTP data directory (mount your data here)               |

Build and run with Podman (or Docker with `docker build -f Containerfile`):

```sh
podman build -t rftp .
podman run -d --name rftp \
  -p 2121:2121 \
  -v /srv/ftp:/ftp:ro \
  -v /etc/rftp:/conf:ro \
  rftp
```

Then connect with any anonymous FTP client, e.g. `ftp localhost 2121` or
`curl ftp://localhost:2121/`.

- **Data — use `/ftp`**: mount the directory you want to serve at **`/ftp`**
  (read-only recommended, e.g. `-v /srv/ftp:/ftp:ro`). Without a mount, only
  the bundled `README.md` is served.
- **Configuration — use `/conf/rftp.yaml`**: put your configuration at
  **`/conf/rftp.yaml`** — mount a directory containing `rftp.yaml` at `/conf`,
  or override the default command, e.g. `podman run ... rftp -config
  /conf/custom.yaml`. See `config.example.yaml` for all options and
  `container/rftp.yaml` for the shipped default.
- **Port**: the default configuration listens on `:2121` inside the container
  (the image runs unprivileged, so ports < 1024 are unavailable). Publish it
  with `-p 2121:2121`, or any host port you prefer, e.g. `-p 21:2121`.
- **Permissions**: the container runs as uid/gid `65534` (nobody). Files under
  `/ftp` must be readable by that uid (world-readable works).
- **Passive mode**: disabled by default. To enable it, set `passive_enabled:
  true` in your configuration and publish the passive port range
  (`passive_port_min`–`passive_port_max`), e.g. `-p 40000-40100:40000-40100`.

The image runs unprivileged in a scratch container: `chroot` and
`read_only_mount` are disabled in the default configuration because they
require root. The server is still read-only and rejects all write commands.

## Testing

```sh
go test ./...
```

Unit tests cover configuration parsing, path sanitization and command parsing;
integration tests cover the FTP protocol end-to-end (login, listings, retrieval,
active/passive mode, rejected write commands, traversal and symlink blocking);
security tests cover chroot and privilege dropping (root-only tests skip when
not run as root).

## Contributing

See [Agents.md](Agents.md) for build/test instructions, project conventions and
the specification workflow.

## License

MIT — see [LICENSE](LICENSE).
