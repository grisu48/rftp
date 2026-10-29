//go:build linux

package security

import (
	"fmt"
	"syscall"
)

// RemountReadOnly re-mounts dir as read-only by bind-mounting it onto
// itself and re-mounting the bind with MS_RDONLY. It requires root and
// CAP_SYS_ADMIN.
func RemountReadOnly(dir string) error {
	if err := syscall.Mount(dir, dir, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mount %s: %w", dir, err)
	}
	if err := syscall.Mount(dir, dir, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount %s read-only: %w", dir, err)
	}
	return nil
}
