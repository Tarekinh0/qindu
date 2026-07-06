package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Tarekinh0/qindu/internal/logging"
	"github.com/Tarekinh0/qindu/internal/policy"
	"github.com/Tarekinh0/qindu/internal/proxy"
	"github.com/Tarekinh0/qindu/internal/service"
	qinduTls "github.com/Tarekinh0/qindu/internal/tls"
	"github.com/Tarekinh0/qindu/internal/vault"
)

// =============================================================================
// Proxy mode (existing QINDU-0001 functionality with enhanced path resolution)
// =============================================================================

// runProxy starts the Qindu proxy in console or Windows service mode.
// If forceConsole is true, service detection is bypassed and the process
// runs in foreground console mode (useful for SSH sessions and debugging).
func runProxy(explicitConfigPath string, forceConsole bool) int {
	configPath, err := resolveConfigPath(explicitConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		return 1
	}

	// Initialize structured logging with config-controlled output destination.
	// When running as a Windows service, os.Stderr is discarded, so the user
	// can configure "output: file" in config to persist logs to disk.
	// The returned closer must be called on shutdown to release the log file handle.
	logger, logCloser := logging.InitLogger(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output, cfg.Logging.LogDir)
	defer func() { _ = logCloser.Close() }()
	logger.Info("Qindu starting",
		"version", appVersion,
		"listen_addr", cfg.ListenAddress(),
	)

	// Initialize CA (load existing or create new, no Name Constraints for proxy runtime)
	ca, err := initCA(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize CA", "error", err)
		return 1
	}

	// Initialize certificate cache
	certCache := qinduTls.NewCertCache()

	// Parse vault TTL from config (defaults to 168h).
	vaultTTL, err := cfg.Agent.Vault.ParseTTL()
	if err != nil {
		logger.Error("failed to parse vault TTL", "error", err)
		return 1
	}
	if vaultTTL == 0 {
		logger.Warn("vault TTL set to 0 (infinite) — PII token mappings will never expire",
			"pii_values_logged", false,
		)
	}

	// Create the VaultManager for per-user vault storage.
	// Only used in enforce mode; passed as nil-safe to NewProxy.
	vaultManager := vault.NewVaultManager(vaultTTL, vault.DefaultIdleTimeout, logger)
	defer vaultManager.Shutdown()

	// SeImpersonatePrivilege warning (SR-CISO-12, R-033).
	// On Windows enforce mode, per-user vault isolation requires the service account
	// to hold SeImpersonatePrivilege. If revoked by GPO, all enforce connections
	// will be rejected with 502 (fail-closed, no PII leakage).
	// TODO: Add runtime detection of SeImpersonatePrivilege via OpenProcessToken +
	// LookupPrivilegeValue. Currently log a blanket warning on Windows enforce mode.
	if cfg.Agent.Mode == "enforce" {
		logger.Warn("enforce mode: per-user vault isolation requires SeImpersonatePrivilege — if absent, all enforce connections will be rejected (fail-closed, pii_values_logged=false)",
			"pii_values_logged", false,
		)
	}

	// If pii_logging is explicitly enabled, warn the operator.
	if cfg.Logging.PIILogging != nil && *cfg.Logging.PIILogging {
		logger.Info("pii_logging is enabled — entity type counts will appear in monitor_scan logs. PII values are never logged.",
			"pii_values_logged", false,
		)
	}

	// Create the proxy.
	proxyHandler, err := proxy.NewProxy(cfg, ca, certCache, vaultManager, logger, appVersion)
	if err != nil {
		logger.Error("failed to create proxy", "error", err)
		return 1
	}

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.ListenAddress(),
		Handler: proxyHandler,
	}

	// Start the proxy (service or console mode). Blocks until shutdown.
	if err := startProxy(server, logger, forceConsole); err != nil {
		logger.Error("proxy failed", "error", err)
		return 1
	}

	// Shutdown cleanup.
	logger.Info("shutdown complete", "pii_values_logged", false)

	return 0
}

// initCA creates or loads the CA based on platform.
func initCA(cfg *policy.Config, logger *slog.Logger) (*qinduTls.CA, error) {
	caDir := getCADir()
	crlPath := filepath.Join(caDir, qinduTls.CRLFilename)
	store := qinduTls.NewCAStore(caDir)
	return qinduTls.CreateOrLoadCA(store, cfg.TLS.CAName, cfg.TLS.CAValidityYears, crlPath, logger)
}

// startProxy starts the proxy in the appropriate mode (service or console).
// If forceConsole is true, runs in console mode regardless of session detection.
func startProxy(server *http.Server, logger *slog.Logger, forceConsole bool) error {
	isService, err := service.IsServiceSession()
	if err != nil {
		// Not on Windows or error checking - run in console mode
		logger.Info("running in console mode (non-Windows or detection failed)")
		return runConsole(server, logger)
	}

	if forceConsole {
		logger.Info("running in console mode (forced)")
		return runConsole(server, logger)
	}

	if isService {
		logger.Info("running as Windows service")
		return runServiceMode(server, logger)
	}

	logger.Info("running in console mode")
	return runConsole(server, logger)
}

// runConsole starts the HTTP server in the foreground with graceful shutdown.
func runConsole(server *http.Server, logger *slog.Logger) error {
	// Start server in goroutine
	go func() {
		logger.Info("proxy listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}()

	// Wait for shutdown signal (SIGINT/SIGTERM)
	return proxy.WaitForShutdown(server, logger)
}

// runServiceMode starts the proxy as a Windows service.
func runServiceMode(server *http.Server, logger *slog.Logger) error {
	return service.RunService("QinduAgent", server, logger)
}
