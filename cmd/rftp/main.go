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

	"anonftp/cmd/rftp/config"
	"anonftp/cmd/rftp/logger"
	"anonftp/cmd/rftp/security"
	"anonftp/cmd/rftp/server"
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
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	logger.SetLevel(cfg.LogLevel)

	// 1. Bind the listener (requires root for ports < 1024).
	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", cfg.ListenAddr, err)
	}

	// 2-4. Security hardening when running as root:
	// chroot, re-mount read-only, then drop privileges.
	if security.IsRoot() {
		if cfg.Chroot {
			if err := security.Chroot(cfg.ServeDir); err != nil {
				return fmt.Errorf("chroot failed (fatal): %w", err)
			}
			// After chroot the served directory is the process root.
			cfg.ServeDir = "/"
			logger.Info("chrooted into served directory dir=/")
		}
		if cfg.ReadOnlyMount {
			if err := security.RemountReadOnly(cfg.ServeDir); err != nil {
				logger.Warn("read-only mount failed, continuing: %v", err)
			} else {
				logger.Info("served directory re-mounted read-only dir=%s", cfg.ServeDir)
			}
		}
		if err := security.DropPrivileges(cfg.User, cfg.Group); err != nil {
			return fmt.Errorf("privilege drop failed (fatal): %w", err)
		}
		logger.Info("dropped privileges user=%s group=%s", cfg.User, cfg.Group)
	} else {
		logger.Warn("not running as root: chroot and privilege drop skipped")
	}

	// 5. Graceful shutdown on SIGTERM/SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("shutdown signal received signal=%s", sig.String())
		srv.Close()
	}()

	logger.Info("starting anonymous read-only FTP server version=1.0 passive_enabled=%t",
		cfg.PassiveEnabled)

	// 6. Serve until shutdown.
	if err := srv.Serve(); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
