# Agents.md — working on rftp

Instructions for AI agents (and humans) contributing to **rftp**: a minimal,
security-focused, **read-only anonymous FTP server** written in Go.

- **Module / repository**: `github.com/grisu48/rftp`
- **License**: MIT (see `LICENSE`)
- **Primary platform**: Linux — chroot, privilege dropping and the read-only
  re-mount in a private mount namespace are Linux-only (`security/` has
  `//go:build linux` files)

## Project layout

```text
cmd/rftp/
├── main.go        # entry point: -config flag, security hardening, signal handling
├── config/        # YAML config loading, defaults, validation
├── ftp/           # FTP protocol constants, command parser, types
├── logger/        # leveled logging (info/debug -> stdout, warn/error -> stderr)
├── security/      # Linux hardening: chroot, read-only mount in a private mount namespace, startup re-exec, privilege drop, fail-closed Apply
└── server/        # dual-stack listener, server lifecycle, sessions, command handlers, passive ports
container/
└── rftp.yaml      # minimal default configuration shipped in the container image
openspec/          # OpenSpec change: proposal, design, capability spec, tasks (source of truth)
Containerfile      # multi-stage build: BCI golang build stage, scratch runtime stage
```

## Build, vet, test

```sh
go build -o rftp ./cmd/rftp
go vet ./...
gofmt -l .        # must print nothing
go test ./...
```

The suite contains unit tests, in-process FTP integration tests (real TCP
sessions), and security tests. Root-only tests (chroot, privilege drop,
read-only mount in a private mount namespace, startup re-exec, fail-closed
hardening) **skip automatically** when not run as root — run
`sudo go test ./...` to exercise them. The namespace tests assert that the
host mount namespace stays writable while the server sees the directory
read-only.

## Configuration

A single YAML file is passed via `-config` (default: `config.yaml`); see
`config.example.yaml`. Only `listen_addr` and `serve_dir` are required.
`user`/`group` are optional (default `nobody`/`nogroup`). Passive mode is
disabled by default (`passive_enabled: false`).

## Security model — non-negotiable

- **Read-only**: write commands (`STOR`, `APPE`, `STOU`, `DELE`, `RNFR`,
  `RNTO`, `MKD`, `RMD`, `SITE`) are rejected with `550 Read-only file system`.
- **Anonymous only**: only `anonymous`/`ftp` are accepted; any other user gets
  `530 Anonymous access only` and the connection is closed.
- **Secure by default (fail-closed)**: every configured security measure
  (chroot, read-only mount, privilege drop) MUST be applied or the program
  exits with a non-zero status. The server MUST NOT serve as root: a root start
  always drops privileges (configured or default `nobody`/`nogroup` target);
  an unprivileged start with `chroot`/`read_only_mount` enabled refuses to start.
- **Namespace-scoped isolation**: as root with `chroot`/`read_only_mount`
  enabled, the process re-execs itself at startup (same PID) after applying
  `unshare(CLONE_NEWNS)` + private propagation + chroot + read-only re-mount on
  a locked thread (`security/namespace.go`), because `unshare(2)`/`chroot(2)`
  are per-thread. The read-only re-mount therefore never affects the rest of
  the system; the config is passed to the re-executed image via the
  `RFTP_CONFIG` env var (`config.InlineEnv`).
- **Path safety**: traversal above the served root (`CWD ../../etc`) and
  symlinks escaping it are rejected with `550 Access denied`.
- **Plain FTP only**: `AUTH TLS`/`PROT`/`PBSZ` are rejected with
  `502 TLS not supported`.

## Conventions

- Standard Go style: `gofmt` and `go vet` must stay clean.
- Standard library only; the single external dependency is `gopkg.in/yaml.v3`.
- Logging goes to stdout (info/debug) and stderr (warn/error) only — never to
  log files. Do not log `PASS` arguments.
- FTP replies follow RFC 959 (plus `EPSV`/`EPRT` per RFC 2428, `LPRT` per
  RFC 1639, UTF-8 per RFC 2640); multi-line replies use `ddd-` continuation
  lines. Recognized-but-unimplemented commands (`LPSV`, `STAT`, `ABOR`,
  `ALLO`, `ACCT`, `SMNT`, `REIN`, `MLSD`, `MLST`, `REST`) get `502 Command
  not implemented` — never `500` — so standard clients can fall back
  (`EPSV -> PASV -> LPSV`, `EPRT -> PORT -> LPRT`). Unknown commands get
  `500 Command not recognized`.
- Keep the codebase minimal: no features beyond the specification, no plugin
  system, no TLS in this version.

## Specification workflow (OpenSpec)

The specification in `openspec/` is the **source of truth**:

- `openspec/project.md` — project context, conventions, constraints
- `openspec/changes/init-anonymous-ftp-server/proposal.md` — what and why
- `openspec/changes/init-anonymous-ftp-server/design.md` — design decisions
- `openspec/changes/init-anonymous-ftp-server/specs/ftp-server/spec.md` —
  normative requirements and scenarios
- `openspec/changes/init-anonymous-ftp-server/tasks.md` — implementation checklist

When changing behavior: update the spec together with the code, keep
`design.md`, `spec.md`, `README.md` and `tasks.md` in sync, and make sure
`go test ./...` passes. The integration tests in `cmd/rftp/server/` encode the
spec scenarios — extend them for new behavior.
