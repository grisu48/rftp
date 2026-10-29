//go:build linux

package security

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --- Non-root behavior (fail-closed) -----------------------------------------
//
// These tests run whenever the test binary is not root: root-only measures
// that are enabled in configuration must be refused, and only an explicit
// opt-out (chroot: false, read_only_mount: false) may continue.

func TestApplyNonRootChrootEnabledRefuses(t *testing.T) {
	if IsRoot() {
		t.Skip("test only meaningful when not running as root")
	}
	_, err := Apply(Hardening{
		ServeDir: t.TempDir(),
		User:     "nobody",
		Group:    "nogroup",
		Chroot:   true,
	})
	if err == nil {
		t.Fatal("Apply must refuse to continue when chroot is enabled but cannot be applied without root")
	}
	if !strings.Contains(err.Error(), "chroot") {
		t.Errorf("error should mention chroot, got: %v", err)
	}
}

func TestApplyNonRootReadOnlyMountEnabledRefuses(t *testing.T) {
	if IsRoot() {
		t.Skip("test only meaningful when not running as root")
	}
	_, err := Apply(Hardening{
		ServeDir:      t.TempDir(),
		User:          "nobody",
		Group:         "nogroup",
		ReadOnlyMount: true,
	})
	if err == nil {
		t.Fatal("Apply must refuse to continue when read_only_mount is enabled but cannot be applied without root")
	}
	if !strings.Contains(err.Error(), "read_only_mount") {
		t.Errorf("error should mention read_only_mount, got: %v", err)
	}
}

func TestApplyNonRootBothMeasuresEnabledRefuses(t *testing.T) {
	if IsRoot() {
		t.Skip("test only meaningful when not running as root")
	}
	_, err := Apply(Hardening{
		ServeDir:      t.TempDir(),
		User:          "nobody",
		Group:         "nogroup",
		Chroot:        true,
		ReadOnlyMount: true,
	})
	if err == nil {
		t.Fatal("Apply must refuse when any root-only measure is enabled without root")
	}
}

func TestApplyNonRootMeasuresDisabledSucceeds(t *testing.T) {
	if IsRoot() {
		t.Skip("test only meaningful when not running as root")
	}
	dir := t.TempDir()
	serveDir, err := Apply(Hardening{
		ServeDir: dir,
		User:     "nobody",
		Group:    "nogroup",
		Chroot:   false,
	})
	if err != nil {
		t.Fatalf("Apply with root-only measures explicitly disabled should succeed: %v", err)
	}
	if serveDir != dir {
		t.Errorf("serveDir = %q, want unchanged %q", serveDir, dir)
	}
}

// --- Root behavior (fail-closed), via subprocess helpers ----------------------

func TestApplyAsRootHardeningSucceeds(t *testing.T) {
	if !IsRoot() {
		t.Skip("security hardening test requires root")
	}
	base := t.TempDir()
	jail := filepath.Join(base, "jail")
	if err := os.Mkdir(jail, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jail, "inside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(),
		"GO_ANONFTP_HELPER=harden-ok",
		"GO_ANONFTP_DIR="+jail,
		"GO_ANONFTP_USER=nobody",
		"GO_ANONFTP_GROUP=nogroup",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("harden-ok helper failed: %v\n%s", err, out)
	}
}

func TestApplyAsRootFailuresAreFatal(t *testing.T) {
	if !IsRoot() {
		t.Skip("fail-closed hardening tests require root")
	}
	// Each mode configures a measure that must fail; Apply must return an
	// error (and the caller must exit) instead of continuing degraded.
	for _, mode := range []string{"harden-chroot-fail", "harden-mount-fail", "harden-privdrop-fail"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
			cmd.Env = append(os.Environ(), "GO_ANONFTP_HELPER="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helper %s failed: %v\n%s", mode, err, out)
			}
		})
	}
}

// --- Helper-process implementations --------------------------------------------

// helperHardenOK applies the full hardening sequence (chroot + privilege
// drop) and verifies the process ended up chrooted and unprivileged.
func helperHardenOK(t *testing.T) {
	serveDir, err := Apply(Hardening{
		ServeDir:      os.Getenv("GO_ANONFTP_DIR"),
		User:          os.Getenv("GO_ANONFTP_USER"),
		Group:         os.Getenv("GO_ANONFTP_GROUP"),
		Chroot:        true,
		ReadOnlyMount: false,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Apply: %v\n", err)
		os.Exit(1)
	}
	if serveDir != "/" {
		fmt.Fprintf(os.Stderr, "serveDir = %q, want / after chroot\n", serveDir)
		os.Exit(2)
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		fmt.Fprintf(os.Stderr, "still root after Apply (privilege drop skipped!)\n")
		os.Exit(3)
	}
	wd, err := os.Getwd()
	if err != nil || wd != "/" {
		fmt.Fprintf(os.Stderr, "getwd = %q, %v; want /\n", wd, err)
		os.Exit(4)
	}
	os.Exit(0)
}

// helperHardenFail configures a measure that must fail and verifies that
// Apply returns an error (fail-closed) instead of continuing.
func helperHardenFail(t *testing.T, mode string) {
	h := Hardening{
		ServeDir: filepath.Join(os.TempDir(), "anonftp-harden-nonexistent-xyz"),
		User:     "nobody",
		Group:    "nogroup",
	}
	switch mode {
	case "chroot":
		h.Chroot = true
	case "mount":
		h.ReadOnlyMount = true
	case "privdrop":
		h.User = "definitely-not-a-user-xyz-123"
	}
	if _, err := Apply(h); err == nil {
		fmt.Fprintf(os.Stderr, "Apply succeeded but %s was configured to fail (fail-closed violated)\n", mode)
		os.Exit(1)
	}
	os.Exit(0)
}
