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

const VERSION = "1.0"

func main() {
	configPath := flag.String("config", "", "path to the YAML configuration file (optional; when omitted, configuration is taken from RFTP_* environment variables)")
	flag.Parse()

	if err := run(*configPath); err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	// The startup re-exec passes the merged configuration to the new image
	// via RFTP_* environment variables (after chroot the config file path
	// may no longer be resolvable), so the re-executed image loads the
	// configuration from the environment alone and ignores -config. In a
	// normal start, the configuration comes from the RFTP_* environment
	// variables and, when -config is given, from the config file (which
	// takes precedence per key).
	var cfg *config.Config
	var err error
	if security.Reexeced() {
		cfg, err = config.LoadWithEnv("", os.LookupEnv)
	} else {
		cfg, err = config.LoadWithEnv(configPath, os.LookupEnv)
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
	if security.NeedsReexec(hardening) {
		inline := *cfg
		if cfg.Chroot {
			inline.ServeDir = "/" // the re-executed image is already chrooted
		}
		if err := inline.SetEnv(); err != nil {
			return fmt.Errorf("cannot pass config to startup re-exec via environment: %w", err)
		}
		if err := security.Reexec(hardening); err != nil {
			return err
		}
	}

	// 2. Bind the listener.
	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", cfg.ListenAddr, err)
	}

	// 3. Security hardening: drop privileges (the chroot and read-only
	// re-mount were applied process-wide by the startup re-exec).
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

	logger.Info("starting ftp server version %s passive_enabled=%t",
		VERSION, cfg.PassiveEnabled)

	// 5. Serve until shutdown.
	if err := srv.Serve(); err != nil {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}
