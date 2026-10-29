package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempConfig writes content to a temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := writeTempConfig(t, `
listen_addr: "127.0.0.1:2121"
passive_enabled: true
passive_port_min: 41000
passive_port_max: 41050
serve_dir: `+dir+`
user: nobody
group: nogroup
chroot: false
read_only_mount: false
log_level: debug
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:2121" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if !cfg.PassiveEnabled {
		t.Error("PassiveEnabled = false, want true")
	}
	if cfg.PassivePortMin != 41000 || cfg.PassivePortMax != 41050 {
		t.Errorf("passive ports = %d-%d", cfg.PassivePortMin, cfg.PassivePortMax)
	}
	if cfg.ServeDir != dir {
		t.Errorf("ServeDir = %q, want %q", cfg.ServeDir, dir)
	}
	if cfg.Chroot || cfg.ReadOnlyMount {
		t.Error("Chroot/ReadOnlyMount should be false")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := writeTempConfig(t, "serve_dir: "+dir+"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":21" {
		t.Errorf("default ListenAddr = %q, want :21", cfg.ListenAddr)
	}
	if cfg.PassiveEnabled {
		t.Error("passive mode should be disabled by default")
	}
	if cfg.PassivePortMin != 40000 || cfg.PassivePortMax != 40100 {
		t.Errorf("default passive ports = %d-%d", cfg.PassivePortMin, cfg.PassivePortMax)
	}
	if cfg.User != "nobody" || cfg.Group != "nogroup" {
		t.Errorf("default user/group = %s/%s", cfg.User, cfg.Group)
	}
	if !cfg.Chroot {
		t.Error("chroot should default to true")
	}
	if !cfg.ReadOnlyMount {
		t.Error("read_only_mount should default to true")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("default LogLevel = %q", cfg.LogLevel)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	if !strings.Contains(err.Error(), "cannot read config file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "listen_addr: [unclosed\n  bad: : :\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "cannot parse config file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()

	// Missing serve_dir.
	path := writeTempConfig(t, "listen_addr: ':2121'\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "serve_dir is required") {
		t.Errorf("expected serve_dir required error, got: %v", err)
	}

	// Missing listen_addr.
	path = writeTempConfig(t, "serve_dir: "+dir+"\n")
	cfg := Default()
	cfg.ServeDir = dir
	cfg.ListenAddr = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "listen_addr is required") {
		t.Errorf("expected listen_addr required error, got: %v", err)
	}
}

func TestValidateServeDirProblems(t *testing.T) {
	// Does not exist.
	cfg := Default()
	cfg.ServeDir = filepath.Join(t.TempDir(), "no-such-dir")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "not accessible") {
		t.Errorf("expected not-accessible error, got: %v", err)
	}

	// Exists but is a regular file.
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg = Default()
	cfg.ServeDir = f
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected not-a-directory error, got: %v", err)
	}
}

func TestValidateLogLevel(t *testing.T) {
	cfg := Default()
	cfg.ServeDir = t.TempDir()
	cfg.LogLevel = "verbose"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "log_level") {
		t.Errorf("expected log_level error, got: %v", err)
	}
}

func TestValidatePassivePortRange(t *testing.T) {
	cfg := Default()
	cfg.ServeDir = t.TempDir()
	cfg.PassiveEnabled = true
	cfg.PassivePortMin = 5000
	cfg.PassivePortMax = 4000
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "passive_port_min") {
		t.Errorf("expected passive range error, got: %v", err)
	}

	cfg.PassivePortMin = 0
	cfg.PassivePortMax = 100
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "passive_port_min") {
		t.Errorf("expected passive_port_min error, got: %v", err)
	}

	cfg.PassivePortMin = 4000
	cfg.PassivePortMax = 5000
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid passive range rejected: %v", err)
	}
}

func TestValidateUserGroupRequired(t *testing.T) {
	cfg := Default()
	cfg.ServeDir = t.TempDir()
	cfg.User = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "user is required") {
		t.Errorf("expected user required error, got: %v", err)
	}
	cfg = Default()
	cfg.ServeDir = t.TempDir()
	cfg.Group = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "group is required") {
		t.Errorf("expected group required error, got: %v", err)
	}
}

func TestServeDirMadeAbsolute(t *testing.T) {
	// A relative serve_dir must be converted to an absolute path so it
	// keeps resolving correctly (and is validated) before any chroot.
	dir := t.TempDir()
	rel, err := filepath.Rel(mustGetwd(t), dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.ServeDir = rel
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !filepath.IsAbs(cfg.ServeDir) {
		t.Errorf("ServeDir = %q, want absolute path", cfg.ServeDir)
	}
	if cfg.ServeDir != dir {
		t.Errorf("ServeDir = %q, want %q", cfg.ServeDir, dir)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
