// SPDX-License-Identifier: MIT

// Package config handles loading and validation of the YAML configuration file.
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

// Bandwidth is a bandwidth limit in bytes per second. The zero value means
// unlimited. In the YAML configuration it may be given as a bare number of
// bytes per second or as a human-readable string such as "512KiB/s" or
// "10MB/s" (units B/KB/MB/GB/TB are decimal, KiB/MiB/GiB/TiB are binary,
// case-insensitive, with an optional "/s" suffix).
type Bandwidth int64

// MarshalYAML serializes the limit as a plain number of bytes per second,
// so Encode/Parse round-trips losslessly through the re-exec environment.
func (b Bandwidth) MarshalYAML() (any, error) {
	return int64(b), nil
}

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
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
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

	// PassiveEnabled controls whether PASV/EPSV are accepted.
	PassiveEnabled bool `yaml:"passive_enabled"`
	// PassivePortMin and PassivePortMax define the passive port range.
	PassivePortMin int `yaml:"passive_port_min"`
	PassivePortMax int `yaml:"passive_port_max"`

	// BandwidthLimit caps the rate of each individual connection (control
	// and data connections alike) in bytes per second. 0 (the default)
	// means unlimited.
	BandwidthLimit Bandwidth `yaml:"bandwidth_limit"`

	// ServeDir is the single directory that is served (and chrooted into
	// when running as root).
	ServeDir string `yaml:"serve_dir"`

	// User and Group are the privileges dropped to after binding/chroot.
	User  string `yaml:"user"`
	Group string `yaml:"group"`

	// Chroot enables chrooting into ServeDir (requires root).
	Chroot bool `yaml:"chroot"`
	// ReadOnlyMount enables re-mounting ServeDir read-only (requires root).
	ReadOnlyMount bool `yaml:"read_only_mount"`

	// LogLevel is one of: debug, info, warn, error.
	LogLevel string `yaml:"log_level"`
}

// Default returns a Config populated with the default values.
func Default() *Config {
	return &Config{
		ListenAddr:     ":21",
		PassiveEnabled: false,
		PassivePortMin: 40000,
		PassivePortMax: 40100,
		BandwidthLimit: 0, // unlimited
		User:           "nobody",
		Group:          "nogroup",
		Chroot:         true,
		ReadOnlyMount:  true,
		LogLevel:       "info",
	}
}

// InlineEnv is the environment variable used to pass the serialized
// configuration to the re-executed process image (see security.Reexec): after
// chroot the config file path may be unreachable, so the new image reads the
// configuration from this variable instead of from a file.
const InlineEnv = "RFTP_CONFIG"

// Load reads, parses and validates the configuration file at path.
// Missing files, invalid YAML and invalid values are reported as errors.
func Load(path string) (*Config, error) {
	// #nosec G304 -- path is the operator-supplied -config flag value, not remote input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file %s: %w", path, err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("cannot parse config file %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", path, err)
	}
	return cfg, nil
}

// Parse unmarshals and validates configuration from YAML data. It is used for
// the configuration passed to the re-executed process image via InlineEnv,
// where no file is involved.
func Parse(data []byte) (*Config, error) {
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

// Encode serializes c to YAML; the result can be passed to the re-executed
// process image via InlineEnv and parsed back with Parse.
func Encode(c *Config) ([]byte, error) {
	return yaml.Marshal(c)
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
	// back to the unprivileged defaults (keep in sync with
	// security.DefaultUser / security.DefaultGroup).
	if c.User == "" {
		c.User = "nobody"
	}
	if c.Group == "" {
		c.Group = "nogroup"
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
