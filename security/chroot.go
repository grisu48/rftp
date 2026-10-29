//go:build linux

// Package security implements the privilege-dropping, chroot and
// read-only mount hardening used at startup.
package security

import (
	"fmt"
	"syscall"
)

// Chroot changes the root directory of the current process to dir and
// moves the working directory to the new root.
//
// It requires root (CAP_SYS_CHROOT) and permanently affects the whole
// process; it is intended to be called once during startup, before
// dropping privileges.
func Chroot(dir string) error {
	if err := syscall.Chroot(dir); err != nil {
		return fmt.Errorf("chroot into %s: %w", dir, err)
	}
	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("chdir to new root: %w", err)
	}
	return nil
}
