// SPDX-License-Identifier: MIT

// Package config handles loading and validation of the YAML configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

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
	f.Close()

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
