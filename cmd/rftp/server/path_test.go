// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/grisu48/rftp/cmd/rftp/config"
)

func TestResolvePath(t *testing.T) {
	tests := []struct {
		name    string
		cwd     string
		arg     string
		want    string
		wantErr bool
	}{
		{"empty arg stays", "/pub", "", "/pub", false},
		{"relative file", "/pub", "file.txt", "/pub/file.txt", false},
		{"absolute path", "/pub", "/etc/passwd", "/etc/passwd", false},
		{"dot segments cleaned", "/pub", "a/./b", "/pub/a/b", false},
		{"inner dotdot ok", "/pub", "a/../b", "/pub/b", false},
		{"parent ok", "/pub", "..", "/", false},
		{"parent within root", "/pub/docs", "..", "/pub", false},
		{"trailing slash", "/pub", "sub/", "/pub/sub", false},
		{"root stays root", "/", "", "/", false},
		{"dotdot clamped inside root", "/a/b/c", "../../../etc/passwd", "/etc/passwd", false},

		// Traversal above the root must be rejected.
		{"escape from root", "/", "../../etc", "", true},
		{"escape from root absolute", "/", "/../../etc", "", true},
		{"escape from subdir", "/pub", "../../etc", "", true},
		{"escape two levels", "/pub/docs", "../../..", "", true},
		{"dotdot at root", "/", "..", "", true},
		{"deep escape", "/a/b/c", "../../../../etc/passwd", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePath(tt.cwd, tt.arg)
			if tt.wantErr {
				if !errors.Is(err, errAccessDenied) {
					t.Fatalf("resolvePath(%q, %q) error = %v, want errAccessDenied", tt.cwd, tt.arg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePath(%q, %q) unexpected error: %v", tt.cwd, tt.arg, err)
			}
			if got != tt.want {
				t.Errorf("resolvePath(%q, %q) = %q, want %q", tt.cwd, tt.arg, got, tt.want)
			}
		})
	}
}

// newTestSession builds a minimal session rooted at dir for path tests.
func newTestSession(dir string) *Session {
	return &Session{srv: &Server{cfg: &config.Config{ServeDir: dir}}}
}

func TestRealPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := newTestSession(root)

	// Plain paths resolve inside the root.
	for _, virtual := range []string{"/", "/inside.txt", "/sub", "/sub/../inside.txt"} {
		if _, err := s.realPath(virtual); err != nil {
			t.Errorf("realPath(%q) unexpected error: %v", virtual, err)
		}
	}

	// Nonexistent path errors.
	if _, err := s.realPath("/missing.txt"); err == nil {
		t.Error("realPath(/missing.txt) expected error")
	}
}

func TestRealPathSymlinkPolicy(t *testing.T) {
	root := t.TempDir()

	// A file inside the root that a symlink points to (allowed).
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file outside the root.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideDir := filepath.Join(outside, "dir")
	if err := os.Mkdir(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Symlink inside root -> file inside root: allowed.
	if err := os.Symlink(filepath.Join(root, "ok.txt"), filepath.Join(root, "ok-link.txt")); err != nil {
		t.Fatal(err)
	}
	// Symlink inside root -> file outside root (absolute): rejected.
	if err := os.Symlink(secret, filepath.Join(root, "escape-link.txt")); err != nil {
		t.Fatal(err)
	}
	// Symlink inside root -> directory outside root (relative): rejected.
	if err := os.Symlink(filepath.Join("..", filepath.Base(outside), "dir"), filepath.Join(root, "escape-dir")); err != nil {
		t.Fatal(err)
	}

	s := newTestSession(root)

	if _, err := s.realPath("/ok-link.txt"); err != nil {
		t.Errorf("symlink to inside file should be allowed, got: %v", err)
	}
	if _, err := s.realPath("/escape-link.txt"); !errors.Is(err, errAccessDenied) {
		t.Errorf("symlink escaping root should be denied, got: %v", err)
	}
	if _, err := s.realPath("/escape-dir"); !errors.Is(err, errAccessDenied) {
		t.Errorf("symlinked dir escaping root should be denied, got: %v", err)
	}
}
