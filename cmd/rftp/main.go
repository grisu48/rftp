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

	// 2. Security hardening: chroot, read-only re-mount, then drop
	// privileges. Secure by default — every configured measure must be
	// applied or the program fails.
	serveDir, err := security.Apply(security.Hardening{
		ServeDir:      cfg.ServeDir,
		User:          cfg.User,
		Group:         cfg.Group,
		Chroot:        cfg.Chroot,
		ReadOnlyMount: cfg.ReadOnlyMount,
	})
	if err != nil {
		return err
	}
	cfg.ServeDir = serveDir

	// 3. Graceful shutdown on SIGTERM/SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("shutdown signal received signal=%s", sig.String())
		srv.Close()
	}()

	logger.Info("starting anonymous read-only FTP server version=1.0 passive_enabled=%t",
		cfg.PassiveEnabled)

	// 4. Serve until shutdown.
	if err := srv.Serve(); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
