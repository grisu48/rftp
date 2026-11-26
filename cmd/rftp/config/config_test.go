// SPDX-License-Identifier: MIT

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
	if cfg.User != DefaultUser || cfg.Group != DefaultGroup {
		t.Errorf("default user/group = %s/%s, want %s/%s", cfg.User, cfg.Group, DefaultUser, DefaultGroup)
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

func TestValidateUserGroupOptional(t *testing.T) {
	// user/group are optional: when unset or explicitly empty they fall
	// back to the unprivileged defaults and must NOT be reported as missing.
	cfg := Default()
	cfg.ServeDir = t.TempDir()
	cfg.User = ""
	cfg.Group = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with empty user/group must succeed: %v", err)
	}
	if cfg.User != DefaultUser || cfg.Group != DefaultGroup {
		t.Errorf("user/group = %q/%q, want defaults %s/%s", cfg.User, cfg.Group, DefaultUser, DefaultGroup)
	}

	// Explicitly configured values are preserved.
	cfg = Default()
	cfg.ServeDir = t.TempDir()
	cfg.User = "ftpd"
	cfg.Group = "ftp"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.User != "ftpd" || cfg.Group != "ftp" {
		t.Errorf("user/group = %q/%q, want configured ftpd/ftp", cfg.User, cfg.Group)
	}

	// Only one of them set: the other falls back to its default.
	cfg = Default()
	cfg.ServeDir = t.TempDir()
	cfg.User = "ftpd"
	cfg.Group = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with only user set: %v", err)
	}
	if cfg.User != "ftpd" || cfg.Group != DefaultGroup {
		t.Errorf("user/group = %q/%q, want ftpd/%s", cfg.User, cfg.Group, DefaultGroup)
	}
}

func TestLoadUserGroupExplicitlyEmpty(t *testing.T) {
	// Explicitly empty user/group in the YAML file must be accepted.
	dir := t.TempDir()
	path := writeTempConfig(t, "serve_dir: "+dir+"\nuser: \"\"\ngroup: \"\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with explicitly empty user/group must succeed: %v", err)
	}
	if cfg.User != DefaultUser || cfg.Group != DefaultGroup {
		t.Errorf("user/group = %q/%q, want defaults %s/%s", cfg.User, cfg.Group, DefaultUser, DefaultGroup)
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

func TestEnvVarsRoundTrip(t *testing.T) {
	// The startup re-exec passes the merged configuration to the new image via
	// RFTP_* environment variables; EnvVars + env-only loading must round-trip
	// the configuration exactly.
	dir := t.TempDir()
	cfg := Default()
	cfg.ListenAddr = "127.0.0.1:2121"
	cfg.PassiveEnabled = true
	cfg.PassivePortMin = 41000
	cfg.PassivePortMax = 41050
	cfg.ServeDir = dir
	cfg.User = "ftpd"
	cfg.Group = "ftp"
	cfg.Chroot = true
	cfg.ReadOnlyMount = true
	cfg.LogLevel = "debug"
	cfg.BandwidthLimit = 10 * 1024 * 1024
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	vars := cfg.EnvVars()
	env := map[string]string{}
	for _, kv := range vars {
		name, value, _ := strings.Cut(kv, "=")
		if _, dup := env[name]; dup {
			t.Fatalf("duplicate environment variable %s in %v", name, vars)
		}
		env[name] = value
	}
	back, err := LoadWithEnv("", envLookup(env))
	if err != nil {
		t.Fatalf("LoadWithEnv: %v", err)
	}
	if *back != *cfg {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", back, cfg)
	}
}

func TestSetEnv(t *testing.T) {
	// SetEnv must export every configuration key into the process environment.
	cfg := Default()
	cfg.ServeDir = t.TempDir()
	cfg.ListenAddr = "127.0.0.1:2121"
	vars := cfg.EnvVars()
	t.Cleanup(func() {
		for _, kv := range vars {
			name, _, _ := strings.Cut(kv, "=")
			os.Unsetenv(name)
		}
	})
	if err := cfg.SetEnv(); err != nil {
		t.Fatalf("SetEnv: %v", err)
	}
	for _, kv := range vars {
		name, value, _ := strings.Cut(kv, "=")
		if got := os.Getenv(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
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

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"0B/s", 0, false},
		{"1048576", 1048576, false},
		{"100B/s", 100, false},
		{"512KiB/s", 512 * 1024, false},
		{"512kib/s", 512 * 1024, false},
		{"10MB/s", 10 * 1000 * 1000, false},
		{"10MiB/s", 10 * 1024 * 1024, false},
		{"2GiB", 2 << 30, false},
		{"1.5kb", 1500, false},
		{"10 MB / s", 10 * 1000 * 1000, false},
		{"1TB/s", 1e12, false},
		{"1TiB/s", 1 << 40, false},
		// Errors: negative, missing number, unknown unit, overflow, garbage.
		{"-5", 0, true},
		{"-5MB/s", 0, true},
		{"MB/s", 0, true},
		{"10XB/s", 0, true},
		{"abc", 0, true},
		{"10.5.2MiB/s", 0, true},
		{"99999999999TiB/s", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseBandwidth(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseBandwidth(%q) = %d, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseBandwidth(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseBandwidth(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestLoadBandwidthLimit(t *testing.T) {
	dir := t.TempDir()
	path := writeTempConfig(t, "serve_dir: "+dir+"\nbandwidth_limit: \"512KiB/s\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BandwidthLimit != 512*1024 {
		t.Errorf("BandwidthLimit = %d, want %d", cfg.BandwidthLimit, 512*1024)
	}

	// A bare number is bytes per second.
	path = writeTempConfig(t, "serve_dir: "+dir+"\nbandwidth_limit: 1048576\n")
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BandwidthLimit != 1048576 {
		t.Errorf("BandwidthLimit = %d, want 1048576", cfg.BandwidthLimit)
	}

	// Omitted means unlimited (0).
	path = writeTempConfig(t, "serve_dir: "+dir+"\n")
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BandwidthLimit != 0 {
		t.Errorf("default BandwidthLimit = %d, want 0 (unlimited)", cfg.BandwidthLimit)
	}
}

func TestLoadInvalidBandwidthLimit(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{`"nonsense"`, `"10XB/s"`, `"-5"`} {
		path := writeTempConfig(t, "serve_dir: "+dir+"\nbandwidth_limit: "+v+"\n")
		if _, err := Load(path); err == nil {
			t.Errorf("Load with bandwidth_limit: %s must fail", v)
		}
	}
}

func TestValidateNegativeBandwidthLimit(t *testing.T) {
	cfg := Default()
	cfg.ServeDir = t.TempDir()
	cfg.BandwidthLimit = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "bandwidth_limit") {
		t.Errorf("expected bandwidth_limit error, got: %v", err)
	}
}

// envLookup returns an environment lookup function backed by the given map.
func envLookup(env map[string]string) func(name string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

func TestEnvName(t *testing.T) {
	cases := map[string]string{
		"listen_addr":     "RFTP_LISTEN_ADDR",
		"serve_dir":       "RFTP_SERVE_DIR",
		"passive_enabled": "RFTP_PASSIVE_ENABLED",
		"bandwidth_limit": "RFTP_BANDWIDTH_LIMIT",
		"read_only_mount": "RFTP_READ_ONLY_MOUNT",
		"log_level":       "RFTP_LOG_LEVEL",
	}
	for key, want := range cases {
		if got := EnvName(key); got != want {
			t.Errorf("EnvName(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestLoadWithEnvOnly(t *testing.T) {
	// No config file: configuration comes from RFTP_* environment variables.
	dir := t.TempDir()
	env := map[string]string{
		"RFTP_LISTEN_ADDR":      "127.0.0.1:2121",
		"RFTP_SERVE_DIR":        dir,
		"RFTP_PASSIVE_ENABLED":  "true",
		"RFTP_PASSIVE_PORT_MIN": "41000",
		"RFTP_PASSIVE_PORT_MAX": "41050",
		"RFTP_BANDWIDTH_LIMIT":  "10MiB/s",
		"RFTP_CHROOT":           "false",
		"RFTP_READ_ONLY_MOUNT":  "false",
		"RFTP_LOG_LEVEL":        "debug",
		"RFTP_USER":             "ftpd",
		"RFTP_GROUP":            "ftp",
	}
	cfg, err := LoadWithEnv("", envLookup(env))
	if err != nil {
		t.Fatalf("LoadWithEnv: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:2121" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.ServeDir != dir {
		t.Errorf("ServeDir = %q, want %q", cfg.ServeDir, dir)
	}
	if !cfg.PassiveEnabled {
		t.Error("PassiveEnabled = false, want true")
	}
	if cfg.PassivePortMin != 41000 || cfg.PassivePortMax != 41050 {
		t.Errorf("passive ports = %d-%d", cfg.PassivePortMin, cfg.PassivePortMax)
	}
	if cfg.BandwidthLimit != 10*1024*1024 {
		t.Errorf("BandwidthLimit = %d, want %d", cfg.BandwidthLimit, 10*1024*1024)
	}
	if cfg.Chroot || cfg.ReadOnlyMount {
		t.Error("Chroot/ReadOnlyMount should be false")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.User != "ftpd" || cfg.Group != "ftp" {
		t.Errorf("user/group = %q/%q", cfg.User, cfg.Group)
	}
}

func TestLoadWithEnvFromProcessEnv(t *testing.T) {
	// The process environment (os.LookupEnv) is the lookup used by main.
	dir := t.TempDir()
	t.Setenv("RFTP_LISTEN_ADDR", ":2121")
	t.Setenv("RFTP_SERVE_DIR", dir)
	t.Setenv("RFTP_PASSIVE_ENABLED", "true")
	cfg, err := LoadWithEnv("", os.LookupEnv)
	if err != nil {
		t.Fatalf("LoadWithEnv: %v", err)
	}
	if cfg.ListenAddr != ":2121" || cfg.ServeDir != dir || !cfg.PassiveEnabled {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestConfigFileTakesPrecedenceOverEnv(t *testing.T) {
	// Keys set in both the file and the environment use the file value;
	// keys set only in the environment keep the environment value.
	dir := t.TempDir()
	path := writeTempConfig(t, `
listen_addr: "127.0.0.1:9999"
passive_enabled: true
bandwidth_limit: 1024
serve_dir: `+dir+`
chroot: false
read_only_mount: false
`)
	env := map[string]string{
		"RFTP_LISTEN_ADDR":     ":2121",   // file wins -> 127.0.0.1:9999
		"RFTP_PASSIVE_ENABLED": "false",   // file wins -> true
		"RFTP_BANDWIDTH_LIMIT": "10MiB/s", // file wins -> 1024
		"RFTP_LOG_LEVEL":       "debug",   // only in env -> debug
		"RFTP_USER":            "ftpd",    // only in env -> ftpd
	}
	cfg, err := LoadWithEnv(path, envLookup(env))
	if err != nil {
		t.Fatalf("LoadWithEnv: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Errorf("ListenAddr = %q, want file value 127.0.0.1:9999", cfg.ListenAddr)
	}
	if !cfg.PassiveEnabled {
		t.Error("PassiveEnabled = false, want file value true")
	}
	if cfg.BandwidthLimit != 1024 {
		t.Errorf("BandwidthLimit = %d, want file value 1024", cfg.BandwidthLimit)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want env value debug", cfg.LogLevel)
	}
	if cfg.User != "ftpd" {
		t.Errorf("User = %q, want env value ftpd", cfg.User)
	}
}

func TestLoadWithEnvInvalidValues(t *testing.T) {
	dir := t.TempDir()
	base := map[string]string{
		"RFTP_LISTEN_ADDR": ":2121",
		"RFTP_SERVE_DIR":   dir,
	}
	cases := map[string]string{
		"RFTP_BANDWIDTH_LIMIT":  "fast",
		"RFTP_PASSIVE_ENABLED":  "maybe",
		"RFTP_PASSIVE_PORT_MIN": "abc",
		"RFTP_CHROOT":           "2",
	}
	for name, value := range cases {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		env[name] = value
		_, err := LoadWithEnv("", envLookup(env))
		if err == nil {
			t.Errorf("LoadWithEnv with %s=%q must fail", name, value)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error for %s=%q should name the variable, got: %v", name, value, err)
		}
	}
}

func TestLoadWithEnvMissingRequiredFields(t *testing.T) {
	// No file and no env: serve_dir has no default and is missing from all
	// sources, so it must be reported.
	if _, err := LoadWithEnv("", envLookup(nil)); err == nil ||
		!strings.Contains(err.Error(), "serve_dir is required") {
		t.Errorf("expected serve_dir required error, got: %v", err)
	}
	// listen_addr explicitly emptied via the environment: missing from all
	// sources, so it must be reported.
	env := map[string]string{"RFTP_SERVE_DIR": t.TempDir(), "RFTP_LISTEN_ADDR": ""}
	if _, err := LoadWithEnv("", envLookup(env)); err == nil ||
		!strings.Contains(err.Error(), "listen_addr is required") {
		t.Errorf("expected listen_addr required error, got: %v", err)
	}
}

func TestLoadWithEnvIgnoresUnknownAndReservedVars(t *testing.T) {
	// Unknown RFTP_* variables (e.g. the RFTP_REEXEC startup guard) are not
	// configuration keys and must be ignored.
	dir := t.TempDir()
	env := map[string]string{
		"RFTP_LISTEN_ADDR": ":2121",
		"RFTP_SERVE_DIR":   dir,
		"RFTP_REEXEC":      "1",
		"RFTP_CONFIG":      "not a config key anymore",
		"RFTP_UNKNOWN":     "whatever",
	}
	cfg, err := LoadWithEnv("", envLookup(env))
	if err != nil {
		t.Fatalf("LoadWithEnv: %v", err)
	}
	if cfg.ListenAddr != ":2121" || cfg.ServeDir != dir {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoadWithEnvEmptyValueUsesDefault(t *testing.T) {
	// An explicitly empty user/group env var behaves like an empty value in
	// the config file: the predefined uid/gid defaults apply.
	dir := t.TempDir()
	env := map[string]string{
		"RFTP_LISTEN_ADDR": ":2121",
		"RFTP_SERVE_DIR":   dir,
		"RFTP_USER":        "",
		"RFTP_GROUP":       "",
	}
	cfg, err := LoadWithEnv("", envLookup(env))
	if err != nil {
		t.Fatalf("LoadWithEnv: %v", err)
	}
	if cfg.User != DefaultUser || cfg.Group != DefaultGroup {
		t.Errorf("user/group = %q/%q, want defaults %s/%s", cfg.User, cfg.Group, DefaultUser, DefaultGroup)
	}
}
