// SPDX-License-Identifier: MIT
//go:build linux

package security

import (
	"fmt"
	"syscall"
)

// RemountReadOnly re-mounts dir as read-only by bind-mounting it onto
// itself and re-mounting the bind with MS_RDONLY. It requires root and
// CAP_SYS_ADMIN.
//
// The re-mount only affects the mount namespace of the calling thread. To
// keep the read-only view private to the server process (and leave the rest
// of the system untouched), call it inside a private mount namespace — see
// EnterPrivateMountNamespace and Reexec.
func RemountReadOnly(dir string) error {
	if err := syscall.Mount(dir, dir, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mount %s: %w", dir, err)
	}
	if err := syscall.Mount(dir, dir, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount %s read-only: %w", dir, err)
	}
	return nil
}

// UnshareMountNamespace moves the calling thread into a new mount namespace
// (CLONE_NEWNS). It requires root and CAP_SYS_ADMIN.
//
// Note that unshare(2) only affects the calling thread; in a multi-threaded
// Go process use Reexec so the whole process ends up in the new namespace.
func UnshareMountNamespace() error {
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare(CLONE_NEWNS): %w", err)
	}
	return nil
}

// MakeMountsPrivate recursively marks every mount in the current mount
// namespace as private (MS_REC|MS_PRIVATE), so mounts created in this
// namespace do not propagate back to the parent namespace and vice versa.
// It must be called immediately after UnshareMountNamespace — on hosts with
// shared mounts (e.g. systemd's default), skipping it would leak the
// read-only re-mount to the whole system.
func MakeMountsPrivate() error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	return nil
}

// EnterPrivateMountNamespace puts the calling thread into a new, private
// mount namespace: unshare(CLONE_NEWNS) followed by making the whole mount
// tree private, so nothing propagates to or from the parent namespace.
func EnterPrivateMountNamespace() error {
	if err := UnshareMountNamespace(); err != nil {
		return err
	}
	return MakeMountsPrivate()
}
