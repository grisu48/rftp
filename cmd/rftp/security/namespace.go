// SPDX-License-Identifier: MIT
//go:build linux

package security

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// reexecEnv is the internal guard environment variable set by Reexec before
// replacing the process image. When it is set, the process is the re-executed
// image in which the namespace/chroot/read-only-mount isolation has already
// been applied, so Apply must not apply those measures again. It is set by
// Reexec itself and is not part of the configuration surface.
const reexecEnv = "RFTP_REEXEC"

// Reexeced reports whether this process is the re-executed image created by
// Reexec, i.e. the isolation measures have already been applied process-wide.
func Reexeced() bool {
	return os.Getenv(reexecEnv) == "1"
}

// NeedsReexec reports whether the process must re-exec itself to apply the
// configured isolation measures to the whole process. That is the case when
// running as root with chroot or read_only_mount enabled, unless the current
// image is already the re-executed one.
func NeedsReexec(h Hardening) bool {
	return IsRoot() && (h.Chroot || h.ReadOnlyMount) && !Reexeced()
}

// Reexec applies the configured isolation measures and then replaces the
// current process image with a fresh copy of the executable (same PID) that
// inherits them:
//
//   - read_only_mount: unshare(CLONE_NEWNS), make the mount tree private,
//     then re-mount the serve directory read-only — all inside the new
//     namespace, so the rest of the system is not affected.
//   - chroot: chroot into the serve directory.
//
// unshare(2) and chroot(2) only affect the calling thread, so they are
// performed here, before the exec, while the thread is locked; the new
// image — and every thread the Go runtime creates afterwards — inherits the
// namespace and root. Doing this inside Apply instead would leave the other
// threads (e.g. the accept loop) in the host namespace/root.
//
// The executable is re-executed through its already-open file descriptor
// (execveat), because after chroot its path may no longer be resolvable.
// The caller must pass any runtime state the new image needs (e.g. the
// configuration) via the environment, since file paths may lie outside the
// new root.
//
// Reexec never returns on success — the process image is replaced. On
// failure it returns an error and the caller must exit (fail-closed).
func Reexec(h Hardening) error {
	if Reexeced() {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Open the executable before any chroot: after chroot its path may be
	// unreachable, so the re-exec goes through this file descriptor. The fd
	// is intentionally opened without O_CLOEXEC so it survives execveat.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	exeFD, err := syscall.Open(exe, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", exe, err)
	}
	defer syscall.Close(exeFD) // only reached when the re-exec fails

	if h.ReadOnlyMount {
		if err := EnterPrivateMountNamespace(); err != nil {
			return fmt.Errorf("secure by default: cannot enter private mount namespace (fatal): %w", err)
		}
	}
	if h.Chroot {
		if err := Chroot(h.ServeDir); err != nil {
			return fmt.Errorf("secure by default: chroot failed (fatal): %w", err)
		}
	}
	if h.ReadOnlyMount {
		dir := h.ServeDir
		if h.Chroot {
			dir = "/" // after chroot the served directory is the process root
		}
		if err := RemountReadOnly(dir); err != nil {
			return fmt.Errorf("secure by default: read-only mount failed (fatal): %w", err)
		}
	}

	env := append(os.Environ(), reexecEnv+"=1")
	if err := fexecve(exeFD, os.Args, env); err != nil {
		return fmt.Errorf("secure by default: startup re-exec failed (fatal): %w", err)
	}
	return nil // unreachable: the image was replaced
}

// atEmptyPath is AT_EMPTY_PATH (0x1000) from <linux/fcntl.h>; the Go
// standard library does not export it on all architectures.
const atEmptyPath = 0x1000

// execveatSyscallNo returns the execveat syscall number for the build
// architecture (the standard library does not export SYS_EXECVEAT on all
// architectures). Values from the kernel uapi headers:
// amd64 = 322 (asm/unistd_64.h), asm-generic (arm64, riscv64, loong64)
// = 281 (asm-generic/unistd.h).
func execveatSyscallNo() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 322, nil
	case "arm64", "riscv64", "loong64":
		return 281, nil
	default:
		return 0, fmt.Errorf("execveat syscall number unknown on %s", runtime.GOARCH)
	}
}

// fexecve replaces the current process image with the executable referred to
// by fd (execveat with AT_EMPTY_PATH). It only returns on error.
func fexecve(fd int, argv, envv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("execveat: empty argv")
	}
	no, err := execveatSyscallNo()
	if err != nil {
		return err
	}
	argvPtrs := make([]*byte, len(argv)+1) // NULL-terminated
	for i, s := range argv {
		p, err := syscall.BytePtrFromString(s)
		if err != nil {
			return err
		}
		argvPtrs[i] = p
	}
	envPtrs := make([]*byte, len(envv)+1) // NULL-terminated
	for i, s := range envv {
		p, err := syscall.BytePtrFromString(s)
		if err != nil {
			return err
		}
		envPtrs[i] = p
	}
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(no,
		uintptr(fd),
		uintptr(unsafe.Pointer(empty)),
		uintptr(unsafe.Pointer(&argvPtrs[0])),
		uintptr(unsafe.Pointer(&envPtrs[0])),
		atEmptyPath,
		0,
	)
	runtime.KeepAlive(argvPtrs)
	runtime.KeepAlive(envPtrs)
	runtime.KeepAlive(empty)
	if errno != 0 {
		return errno
	}
	return nil
}
