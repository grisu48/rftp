// SPDX-License-Identifier: MIT

// Command rftp is a minimal, security-focused, read-only anonymous FTP
// server. It serves a single directory over plain FTP with dual-stack
// IPv4/IPv6 support, dropping privileges and chrooting when run as root.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/grisu48/rftp/cmd/rftp/config"
	"github.com/grisu48/rftp/cmd/rftp/logger"
	"github.com/grisu48/rftp/cmd/rftp/security"
	"github.com/grisu48/rftp/cmd/rftp/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	// The re-executed image receives the configuration via the environment:
	// after chroot the config file path may no longer be resolvable.
	var cfg *config.Config
	var err error
	if inline := os.Getenv(config.InlineEnv); inline != "" {
		cfg, err = config.Parse([]byte(inline))
	} else {
		cfg, err = config.Load(configPath)
	}
	if err != nil {
		return err
	}
	logger.SetLevel(cfg.LogLevel)

	hardening := security.Hardening{
		ServeDir:      cfg.ServeDir,
		User:          cfg.User,
		Group:         cfg.Group,
		Chroot:        cfg.Chroot,
		ReadOnlyMount: cfg.ReadOnlyMount,
	}

	// 1. Startup isolation re-exec: enter a private mount namespace and/or
	// chroot before binding, so those measures apply to the whole process.
	// unshare(2)/chroot(2) are per-thread, so they must happen before the
	// exec, not in Apply. The read-only re-mount is done inside the private
	// namespace, leaving the rest of the system unaffected. The config is
	// passed to the new image via the environment. Reexec never returns on
	// success; on failure the program exits (fail-closed).
	if security.NeedsReexec(hardening) {
		inline := *cfg
		if cfg.Chroot {
			inline.ServeDir = "/" // the re-executed image is already chrooted
		}
		data, err := config.Encode(&inline)
		if err != nil {
			return fmt.Errorf("cannot serialize config for startup re-exec: %w", err)
		}
		if err := os.Setenv(config.InlineEnv, string(data)); err != nil {
			return fmt.Errorf("cannot pass config to startup re-exec: %w", err)
		}
		if err := security.Reexec(hardening); err != nil {
			return err
		}
	}

	// 2. Bind the listener (requires root for ports < 1024).
	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", cfg.ListenAddr, err)
	}

	// 3. Security hardening: drop privileges (the chroot and read-only
	// re-mount were applied process-wide by the startup re-exec).
	// Secure by default — every configured measure must be applied or the
	// program fails.
	serveDir, err := security.Apply(hardening)
	if err != nil {
		return err
	}
	cfg.ServeDir = serveDir

	// 4. Graceful shutdown on SIGTERM/SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("shutdown signal received signal=%s", sig.String())
		srv.Close()
	}()

	logger.Info("starting anonymous read-only FTP server version=1.0 passive_enabled=%t",
		cfg.PassiveEnabled)

	// 5. Serve until shutdown.
	if err := srv.Serve(); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
