// SPDX-License-Identifier: MIT

// Package config handles loading and validation of the server configuration,
// from a YAML configuration file and/or RFTP_* environment variables.
package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Bandwidth limit in bytes per second. Zero means unlimited.
type Bandwidth int64

// UnmarshalYAML parses a bandwidth limit from a YAML scalar: a bare number
// (bytes per second) or a value with a unit suffix, e.g. "10MiB/s".
func (b *Bandwidth) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("bandwidth_limit must be a scalar, e.g. \"10MiB/s\"")
	}
	n, err := ParseBandwidth(value.Value)
	if err != nil {
		return err
	}
	*b = Bandwidth(n)
	return nil
}

// bandwidthUnits maps lower-cased unit suffixes to their multiplier in
// bytes. Decimal units (KB, MB, ...) are 1000-based, binary units (KiB,
// MiB, ...) are 1024-based. The empty unit and "b" mean bytes.
var bandwidthUnits = map[string]float64{
	"": 1, "b": 1,
	"k": 1e3, "kb": 1e3,
	"m": 1e6, "mb": 1e6,
	"g": 1e9, "gb": 1e9,
	"t": 1e12, "tb": 1e12,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
}

// ParseBandwidth parses a bandwidth limit string into bytes per second.
// Accepted forms: a bare number ("1048576"), or "<value><unit>" with an
// optional "/s" suffix ("10MB/s", "512KiB/s", "1.5G"). An empty string or
// "0" means unlimited (0 bytes per second cap). Negative values, unknown
// units and overflow are rejected.
func ParseBandwidth(s string) (int64, error) {
	orig := s
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", "")) // Note: TrimSpace trims all whitespaces
	s = strings.TrimSuffix(s, "/s")
	if s == "" || s == "0" {
		return 0, nil
	}
	// Split the numeric prefix from the unit suffix.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	num, unit := s[:i], s[i:]
	mult, ok := bandwidthUnits[unit]
	if num == "" || !ok {
		return 0, fmt.Errorf("invalid bandwidth_limit %q: want a number with optional unit, e.g. \"10MiB/s\"", orig)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid bandwidth_limit %q: %v", orig, err)
	}
	v := f * mult
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("bandwidth_limit %q is too large", orig)
	}
	return int64(v), nil
}

// Config holds all server configuration.
type Config struct {
	// ListenAddr is the address the control listener binds to
	// (e.g. ":21" or "::"). A wildcard address gives dual-stack IPv4/IPv6.
	ListenAddr string `yaml:"listen_addr"`

	// PassiveEnabled controls if FTP passive mode is enabled
	PassiveEnabled bool `yaml:"passive_enabled"`
	// PassivePortMin and PassivePortMax define the passive port range.
	PassivePortMin int `yaml:"passive_port_min"`
	PassivePortMax int `yaml:"passive_port_max"`

	// BandwidthLimit caps the rate of each individual connection (control
	// and data connections alike) in bytes per second. 0 (the default)
	// means unlimited.
	BandwidthLimit Bandwidth `yaml:"bandwidth_limit"`

	// ServeDir is the single directory that is served.
	ServeDir string `yaml:"serve_dir"`

	// User and Group are the privileges dropped to after binding/chroot.
	// Each may be a name (e.g. "nobody", resolved via the user database) or
	// a numeric ID (e.g. "65534"); when empty they default to the predefined
	// DefaultUser/DefaultGroup.
	User  string `yaml:"user"`
	Group string `yaml:"group"`

	// Chroot enables chrooting into ServeDir (requires root).
	Chroot bool `yaml:"chroot"`
	// ReadOnlyMount enables re-mounting ServeDir read-only (requires root).
	ReadOnlyMount bool `yaml:"read_only_mount"`

	// LogLevel is one of: debug, info, warn, error.
	LogLevel string `yaml:"log_level"`
}

// DefaultUser and DefaultGroup are the privilege drop targets used when
// user/group are not configured: the predefined numeric IDs 65534/65534
// (the conventional nobody/nogroup IDs, i.e. the Linux overflow uid/gid).
// Keep in sync with security.DefaultUID / security.DefaultGID.
const (
	DefaultUser  = "65534"
	DefaultGroup = "65534"
)

// Default returns a Config populated with the default values.
func Default() *Config {
	return &Config{
		ListenAddr:     ":21",
		PassiveEnabled: true,
		PassivePortMin: 40000,
		PassivePortMax: 40100,
		BandwidthLimit: 0, // unlimited
		User:           DefaultUser,
		Group:          DefaultGroup,
		Chroot:         true,
		ReadOnlyMount:  true,
		LogLevel:       "info",
	}
}

// EnvPrefix is the prefix of the environment variables that configure the
// server. Each configuration key maps to an environment variable named
// EnvPrefix + the uppercased key, e.g. "listen_addr" -> "RFTP_LISTEN_ADDR",
// "read_only_mount" -> "RFTP_READ_ONLY_MOUNT".
const EnvPrefix = "RFTP_"

// EnvName returns the environment variable name for a configuration key.
func EnvName(key string) string {
	return EnvPrefix + strings.ToUpper(key)
}

// applyEnv applies configuration from environment variables to cfg. For each
// known configuration key, the variable EnvName(key) is looked up and its
// value is parsed with the same rules as the corresponding YAML field.
// Unknown RFTP_* variables (e.g. the RFTP_REEXEC startup guard) are ignored.
// lookup is typically os.LookupEnv.
func applyEnv(cfg *Config, lookup func(name string) (value string, ok bool)) error {
	// String fields take the raw environment value (an environment variable
	// is already a literal string); other fields are parsed as YAML scalars,
	// so they accept exactly the same values as in the config file.
	setters := map[string]func(value string) error{
		"listen_addr":      func(v string) error { cfg.ListenAddr = v; return nil },
		"serve_dir":        func(v string) error { cfg.ServeDir = v; return nil },
		"user":             func(v string) error { cfg.User = v; return nil },
		"group":            func(v string) error { cfg.Group = v; return nil },
		"log_level":        func(v string) error { cfg.LogLevel = v; return nil },
		"passive_enabled":  func(v string) error { return parseScalar(&cfg.PassiveEnabled, v) },
		"passive_port_min": func(v string) error { return parseScalar(&cfg.PassivePortMin, v) },
		"passive_port_max": func(v string) error { return parseScalar(&cfg.PassivePortMax, v) },
		"bandwidth_limit":  func(v string) error { return parseScalar(&cfg.BandwidthLimit, v) },
		"chroot":           func(v string) error { return parseScalar(&cfg.Chroot, v) },
		"read_only_mount":  func(v string) error { return parseScalar(&cfg.ReadOnlyMount, v) },
	}
	for key, set := range setters {
		name := EnvName(key)
		value, ok := lookup(name)
		if !ok {
			continue
		}
		if err := set(value); err != nil {
			return fmt.Errorf("invalid value %q for environment variable %s (%s): %w", value, name, key, err)
		}
	}
	return nil
}

// parseScalar unmarshals a single YAML scalar (an environment variable value)
// into field, applying the same rules as the corresponding config file field.
func parseScalar(field any, value string) error {
	return yaml.Unmarshal([]byte(value), field)
}

// Load reads, parses and validates the configuration file at path.
// Missing files, invalid YAML and invalid values are reported as errors.
func Load(path string) (*Config, error) {
	return load(path, nil)
}

// LoadWithEnv loads the configuration from environment variables and, when
// path is not empty, from the configuration file at path. Environment
// variables (RFTP_<KEY>) are applied first and the config file is parsed on
// top of them, so the config file takes precedence over environment variables
// on a per-key basis: keys present in both use the file value, and environment
// variables only supply values for keys absent from the file. When path is
// empty, configuration is taken from the environment alone. lookup is
// typically os.LookupEnv.
func LoadWithEnv(path string, lookup func(name string) (value string, ok bool)) (*Config, error) {
	return load(path, lookup)
}

func load(path string, lookup func(name string) (value string, ok bool)) (*Config, error) {
	cfg := Default()
	if lookup != nil {
		if err := applyEnv(cfg, lookup); err != nil {
			return nil, err
		}
	}
	if path != "" {
		// #nosec G304 -- path is the operator-supplied -config flag value, not remote input.
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read config file %s: %w", path, err)
		}
		// Unmarshal only sets the keys present in the file, so the file
		// values override the environment on a per-key basis.
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("cannot parse config file %s: %w", path, err)
		}
	}
	if err := cfg.Validate(); err != nil {
		if path != "" {
			return nil, fmt.Errorf("invalid config file %s: %w", path, err)
		}
		return nil, fmt.Errorf("invalid configuration (provide it via a config file or %s* environment variables): %w", EnvPrefix, err)
	}
	return cfg, nil
}

// EnvVars returns the configuration as RFTP_* environment variable
// assignments ("NAME=value"), one per configuration key. Values are
// formatted so that loading them back from the environment (LoadWithEnv with
// an empty path) reproduces the configuration exactly.
func (c *Config) EnvVars() []string {
	return []string{
		EnvName("listen_addr") + "=" + c.ListenAddr,
		EnvName("passive_enabled") + "=" + strconv.FormatBool(c.PassiveEnabled),
		EnvName("passive_port_min") + "=" + strconv.Itoa(c.PassivePortMin),
		EnvName("passive_port_max") + "=" + strconv.Itoa(c.PassivePortMax),
		EnvName("bandwidth_limit") + "=" + strconv.FormatInt(int64(c.BandwidthLimit), 10),
		EnvName("serve_dir") + "=" + c.ServeDir,
		EnvName("user") + "=" + c.User,
		EnvName("group") + "=" + c.Group,
		EnvName("chroot") + "=" + strconv.FormatBool(c.Chroot),
		EnvName("read_only_mount") + "=" + strconv.FormatBool(c.ReadOnlyMount),
		EnvName("log_level") + "=" + c.LogLevel,
	}
}

// SetEnv exports the configuration as RFTP_* environment variables in the
// current process environment. It is used to pass the merged configuration to
// the startup re-exec (see security.Reexec): after chroot the config file
// path may no longer be resolvable, so the new image reads the configuration
// from these variables instead of from a file.
func (c *Config) SetEnv() error {
	for _, kv := range c.EnvVars() {
		name, value, _ := strings.Cut(kv, "=")
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("cannot set environment variable %s: %w", name, err)
		}
	}
	return nil
}

// Validate checks the configuration for missing or invalid fields.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.ServeDir == "" {
		return fmt.Errorf("serve_dir is required")
	}

	// Make the served directory absolute so it keeps working after chroot.
	abs, err := filepath.Abs(c.ServeDir)
	if err != nil {
		return fmt.Errorf("serve_dir %q: %w", c.ServeDir, err)
	}
	c.ServeDir = abs

	info, err := os.Stat(c.ServeDir)
	if err != nil {
		return fmt.Errorf("serve_dir %q is not accessible: %w", c.ServeDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("serve_dir %q is not a directory", c.ServeDir)
	}
	f, err := os.Open(c.ServeDir)
	if err != nil {
		return fmt.Errorf("serve_dir %q is not readable: %w", c.ServeDir, err)
	}
	_ = f.Close()

	// user/group are optional: when unset (or explicitly empty) they fall
	// back to the predefined unprivileged uid/gid defaults (keep in sync
	// with security.DefaultUID / security.DefaultGID).
	if c.User == "" {
		c.User = DefaultUser
	}
	if c.Group == "" {
		c.Group = DefaultGroup
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be one of: debug, info, warn, error (got %q)", c.LogLevel)
	}

	if c.BandwidthLimit < 0 {
		return fmt.Errorf("bandwidth_limit must not be negative (got %d)", c.BandwidthLimit)
	}

	if c.PassiveEnabled {
		if c.PassivePortMin < 1 || c.PassivePortMin > 65535 {
			return fmt.Errorf("passive_port_min must be between 1 and 65535 (got %d)", c.PassivePortMin)
		}
		if c.PassivePortMax < 1 || c.PassivePortMax > 65535 {
			return fmt.Errorf("passive_port_max must be between 1 and 65535 (got %d)", c.PassivePortMax)
		}
		if c.PassivePortMin > c.PassivePortMax {
			return fmt.Errorf("passive_port_min (%d) must not be greater than passive_port_max (%d)",
				c.PassivePortMin, c.PassivePortMax)
		}
	}

	return nil
}
