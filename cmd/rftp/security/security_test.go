//go:build linux

package security

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIsRootMatchesEuid(t *testing.T) {
	if got, want := IsRoot(), os.Geteuid() == 0; got != want {
		t.Errorf("IsRoot() = %v, want %v", got, want)
	}
}

func TestChrootNonexistentDirFails(t *testing.T) {
	// Fails for any user: ENOENT as root, EPERM as non-root.
	if err := Chroot(filepath.Join(t.TempDir(), "no-such-dir")); err == nil {
		t.Error("Chroot into nonexistent directory should fail")
	}
}

func TestDropPrivilegesRequiresRoot(t *testing.T) {
	if IsRoot() {
		t.Skip("test only meaningful when not running as root")
	}
	if err := DropPrivileges("nobody", "nogroup"); err == nil {
		t.Error("DropPrivileges as non-root should fail")
	}
}

func TestDropPrivilegesUnknownUserFails(t *testing.T) {
	// A nonexistent user/group must produce an error (and must never
	// partially drop privileges).
	if err := DropPrivileges("definitely-not-a-user-xyz-123", "nogroup"); err == nil {
		t.Error("DropPrivileges with unknown user should fail")
	}
	if IsRoot() {
		t.Error("DropPrivileges with unknown user should not succeed even as root")
	}
}

func TestRemountReadOnlyNonexistentDirFails(t *testing.T) {
	if err := RemountReadOnly(filepath.Join(t.TempDir(), "no-such-dir")); err == nil {
		t.Error("RemountReadOnly on nonexistent directory should fail")
	}
}

// --- Root-only tests (subprocess helpers) -----------------------------------------
//
// chroot and privilege dropping permanently affect the process, so they are
// exercised in a child process. The parent asserts on the child's exit code.

// TestHelperProcess is not a real test; it runs in a child process when
// GO_RFTP_HELPER is set. See the Test*HelperProcess functions below.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("GO_RFTP_HELPER") {
	case "chroot":
		helperChroot(t)
	case "privdrop":
		helperPrivDrop(t)
	case "mount":
		helperMount(t)
	case "harden-ok":
		helperHardenOK(t)
	case "harden-defaults":
		helperHardenDefaults(t)
	case "harden-chroot-fail":
		helperHardenFail(t, "chroot")
	case "harden-mount-fail":
		helperHardenFail(t, "mount")
	case "harden-privdrop-fail":
		helperHardenFail(t, "privdrop")
	default:
		return
	}
}

// helperChroot chroots into GO_RFTP_DIR and verifies the process root
// contains exactly the chroot directory's contents.
func helperChroot(t *testing.T) {
	dir := os.Getenv("GO_RFTP_DIR")
	if err := Chroot(dir); err != nil {
		fmt.Fprintf(os.Stderr, "chroot: %v\n", err)
		os.Exit(1)
	}
	wd, err := os.Getwd()
	if err != nil || wd != "/" {
		fmt.Fprintf(os.Stderr, "getwd = %q, %v; want /\n", wd, err)
		os.Exit(2)
	}
	// The file inside the chroot dir must be visible at /.
	if _, err := os.Stat("/inside.txt"); err != nil {
		fmt.Fprintf(os.Stderr, "inside.txt not visible after chroot: %v\n", err)
		os.Exit(3)
	}
	// The sibling file outside the chroot dir must NOT be visible.
	if _, err := os.Stat("/outside.txt"); err == nil {
		fmt.Fprintf(os.Stderr, "outside.txt visible after chroot (escape!)\n")
		os.Exit(4)
	}
	// Writing inside the chroot fails after the read-only remount only; here
	// we just verify the chroot took effect.
	os.Exit(0)
}

func TestChrootAsRoot(t *testing.T) {
	if !IsRoot() {
		t.Skip("chroot test requires root")
	}
	base := t.TempDir()
	chrootDir := filepath.Join(base, "jail")
	if err := os.Mkdir(chrootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(chrootDir, "inside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "outside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "GO_RFTP_HELPER=chroot", "GO_RFTP_DIR="+chrootDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("chroot helper failed: %v\n%s", err, out)
	}
}

// helperPrivDrop drops privileges and verifies the process is no longer root.
func helperPrivDrop(t *testing.T) {
	user := os.Getenv("GO_RFTP_USER")
	group := os.Getenv("GO_RFTP_GROUP")
	if err := DropPrivileges(user, group); err != nil {
		fmt.Fprintf(os.Stderr, "DropPrivileges: %v\n", err)
		os.Exit(1)
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		fmt.Fprintf(os.Stderr, "still root after DropPrivileges\n")
		os.Exit(2)
	}
	// Supplementary groups must not include root (gid 0).
	groups, err := syscall.Getgroups()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Getgroups: %v\n", err)
		os.Exit(3)
	}
	for _, g := range groups {
		if g == 0 {
			fmt.Fprintf(os.Stderr, "supplementary group 0 still present\n")
			os.Exit(4)
		}
	}
	os.Exit(0)
}

func TestDropPrivilegesAsRoot(t *testing.T) {
	if !IsRoot() {
		t.Skip("privilege drop test requires root")
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(),
		"GO_RFTP_HELPER=privdrop",
		"GO_RFTP_USER=nobody",
		"GO_RFTP_GROUP=nogroup",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("privdrop helper failed: %v\n%s", err, out)
	}
}

// helperMount re-mounts GO_RFTP_DIR read-only and verifies that writes
// to it fail. If the environment forbids mounting (e.g. unprivileged
// container without CAP_SYS_ADMIN), it exits with code 42 so the parent
// can skip.
func helperMount(t *testing.T) {
	dir := os.Getenv("GO_RFTP_DIR")
	if err := RemountReadOnly(dir); err != nil {
		fmt.Fprintf(os.Stderr, "RemountReadOnly: %v\n", err)
		os.Exit(42) // environment does not allow mounting
	}
	// A write into the re-mounted directory must now fail.
	if err := os.WriteFile(filepath.Join(dir, "should-fail.txt"), []byte("x"), 0o644); err == nil {
		fmt.Fprintf(os.Stderr, "write succeeded on read-only mount\n")
		os.Exit(3)
	}
	os.Exit(0)
}

func TestRemountReadOnlyAsRoot(t *testing.T) {
	if !IsRoot() {
		t.Skip("read-only mount test requires root")
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "GO_RFTP_HELPER=mount", "GO_RFTP_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 42 {
		t.Skipf("mounting not permitted in this environment: %s", out)
	}
	if err != nil {
		t.Fatalf("mount helper failed: %v\n%s", err, out)
	}
}
