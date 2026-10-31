// SPDX-License-Identifier: MIT
//go:build linux

package security

import (
	"testing"
)

func TestReexecNoopWhenReexeced(t *testing.T) {
	// In the re-executed image Reexec must be a no-op (otherwise the process
	// would re-exec in a loop).
	t.Setenv(reexecEnv, "1")
	if !Reexeced() {
		t.Fatal("Reexeced() = false with guard env set, want true")
	}
	if err := Reexec(Hardening{ServeDir: t.TempDir(), Chroot: true, ReadOnlyMount: true}); err != nil {
		t.Errorf("Reexec in the re-executed image must be a no-op, got: %v", err)
	}
}

func TestNeedsReexecNonRoot(t *testing.T) {
	if IsRoot() {
		t.Skip("test only meaningful when not running as root")
	}
	h := Hardening{ServeDir: t.TempDir(), Chroot: true, ReadOnlyMount: true}
	if NeedsReexec(h) {
		t.Error("NeedsReexec must be false when not running as root (unshare/chroot need CAP_SYS_ADMIN/CAP_SYS_CHROOT)")
	}
}

func TestNeedsReexecAlreadyReexeced(t *testing.T) {
	if !IsRoot() {
		t.Skip("test only meaningful when running as root")
	}
	t.Setenv(reexecEnv, "1")
	h := Hardening{ServeDir: t.TempDir(), Chroot: true, ReadOnlyMount: true}
	if NeedsReexec(h) {
		t.Error("NeedsReexec must be false in the re-executed image (guard env set)")
	}
}

func TestNeedsReexecRootMeasuresDisabled(t *testing.T) {
	if !IsRoot() {
		t.Skip("test only meaningful when running as root")
	}
	// No root-only measure configured: no re-exec needed.
	if NeedsReexec(Hardening{ServeDir: t.TempDir()}) {
		t.Error("NeedsReexec must be false when chroot and read_only_mount are disabled")
	}
}
