//go:build linux

package security

import (
	"fmt"
	"os"

	"anonftp/cmd/rftp/logger"
)

// Hardening configures the startup security hardening sequence.
type Hardening struct {
	// ServeDir is the directory to serve; it becomes "/" after chroot.
	ServeDir string
	// User and Group are the privileges dropped to when running as root.
	User  string
	Group string
	// Chroot enables chrooting into ServeDir (requires root).
	Chroot bool
	// ReadOnlyMount enables re-mounting ServeDir read-only (requires root).
	ReadOnlyMount bool
}

// Apply performs the security hardening sequence — chroot, read-only
// re-mount, privilege drop — and returns the serve directory as seen after
// hardening ("/" when chrooted).
//
// Secure by default (fail-closed): every configured measure MUST be applied.
// If chroot, the read-only re-mount or the privilege drop fails, Apply
// returns an error and the caller must exit. When the process is not root,
// the root-only measures (chroot, read-only mount) must be disabled in the
// configuration, otherwise Apply returns an error; in that case there are no
// root privileges to drop, so the privilege-drop goal is already satisfied
// and this is logged explicitly rather than silently skipped.
func Apply(h Hardening) (string, error) {
	serveDir := h.ServeDir

	if !IsRoot() {
		if h.Chroot {
			return "", fmt.Errorf("chroot is enabled but requires root (start as root or set chroot: false)")
		}
		if h.ReadOnlyMount {
			return "", fmt.Errorf("read_only_mount is enabled but requires root (start as root or set read_only_mount: false)")
		}
		logger.Warn("not running as root (uid=%d): no root privileges to drop; chroot and read-only mount are disabled by configuration", os.Getuid())
		return serveDir, nil
	}

	if h.Chroot {
		if err := Chroot(serveDir); err != nil {
			return "", fmt.Errorf("chroot failed (fatal): %w", err)
		}
		// After chroot the served directory is the process root.
		serveDir = "/"
		logger.Info("chrooted into served directory dir=/")
	}
	if h.ReadOnlyMount {
		if err := RemountReadOnly(serveDir); err != nil {
			return "", fmt.Errorf("read-only mount failed (fatal): %w", err)
		}
		logger.Info("served directory re-mounted read-only dir=%s", serveDir)
	}
	// Privilege dropping is never skipped when running as root: if it fails,
	// the program must exit rather than serve as root.
	if err := DropPrivileges(h.User, h.Group); err != nil {
		return "", fmt.Errorf("privilege drop failed (fatal): %w", err)
	}
	logger.Info("dropped privileges user=%s group=%s", h.User, h.Group)

	return serveDir, nil
}
