package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Tarekinh0/qindu/internal/crypto"
	"github.com/Tarekinh0/qindu/internal/logging"
	"github.com/Tarekinh0/qindu/internal/policy"
	"github.com/Tarekinh0/qindu/internal/proxy"
	"github.com/Tarekinh0/qindu/internal/service"
	"github.com/Tarekinh0/qindu/internal/session"
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

	// ── Vault initialization (QINDU-0008) ──
	// The vault provides encrypted persistent storage for token↔PII mappings.
	// It is optional — if initialization fails, the proxy starts in memory-only
	// mode (vault = nil). The proxy operates identically with or
	// without a vault (DD-2, DD-11).
	vaultInst := initVault(cfg, logger)

	// Create the proxy with optional vault persister.
	proxyHandler, err := proxy.NewProxy(cfg, ca, certCache, logger, appVersion)
	if err != nil {
		logger.Error("failed to create proxy", "error", err)
		if vaultInst != nil {
			vaultInst.Close()
		}
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
		if vaultInst != nil {
			vaultInst.Close()
		}
		return 1
	}

	// Shutdown cleanup: close vault after proxy has stopped.
	if vaultInst != nil {
		logger.Info("shutting down vault", "pii_values_logged", false)
		vaultInst.Close()
	}
	logger.Info("shutdown complete", "pii_values_logged", false)

	return 0
}

// initVault initializes the encrypted vault (QINDU-0008).
// Returns the vault instance (which implements TokenPersister), or nil
// if any initialization step fails. All cleanup (close crypto, close bolt)
// is handled internally on error paths via defer.
// The caller must call vaultInst.Close() during shutdown if non-nil.
// The TokenPersister interface returned by the vault will be wired to
// the tokenizer in QINDU-0009 (enforce mode).
func initVault(cfg *policy.Config, logger *slog.Logger) *vault.Vault {
	ttl, ttlErr := cfg.Agent.Vault.ParseTTL()
	if ttlErr != nil {
		logger.Error("vault: invalid TTL in config — vault disabled",
			"error", ttlErr,
			"pii_values_logged", false,
		)
		return nil
	}

	vaultUser, lookupErr := session.LookupVaultPath()
	if lookupErr != nil {
		logger.Error("vault: cannot determine storage path — vault disabled",
			"error", lookupErr,
			"pii_values_logged", false,
		)
		return nil
	}

	if err := os.MkdirAll(vaultUser.VaultPath, 0700); err != nil {
		logger.Error("vault: cannot create vault directory — vault disabled",
			"error", err,
			"pii_values_logged", false,
		)
		return nil
	}

	// Initialize crypto service for AES-256-GCM encryption.
	cryptoService, cryptoErr := crypto.New(vaultUser.KeyPath)
	if cryptoErr != nil {
		logger.Error("vault: failed to initialize crypto — vault disabled",
			"error", cryptoErr,
			"pii_values_logged", false,
		)
		return nil
	}

	// Open bbolt database.
	db, boltErr := bolt.Open(vaultUser.DBPath, 0600, &bolt.Options{
		Timeout: 1 * time.Second,
		NoSync:  false, // fsync after each commit; required for crash safety (DD-2)
	})
	if boltErr != nil {
		logger.Error("vault: failed to open database — vault disabled",
			"error", boltErr,
			"pii_values_logged", false,
		)
		_ = cryptoService.Close()
		return nil
	}

	if bucketErr := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(vault.BucketTokens))
		return err
	}); bucketErr != nil {
		logger.Error("vault: failed to create bucket — vault disabled",
			"error", bucketErr,
			"pii_values_logged", false,
		)
		_ = db.Close()
		_ = cryptoService.Close()
		return nil
	}

	// Create the vault.
	vaultInst, vaultErr := vault.New(db, cryptoService, ttl, logger)
	if vaultErr != nil {
		logger.Error("vault: failed to initialize — vault disabled",
			"error", vaultErr,
			"pii_values_logged", false,
		)
		_ = db.Close()
		_ = cryptoService.Close()
		return nil
	}

	// Start background goroutines (async writer, TTL sweeper).
	// Background: actual cancellation via vault.Close() → v.cancel().
	vaultInst.Run(context.Background())

	if ttl == 0 {
		logger.Warn("vault TTL set to infinite — PII will persist until manually deleted",
			"pii_values_logged", false,
		)
	}
	logger.Info("vault initialized",
		"db_path", redactHomePath(vaultUser.DBPath),
		"ttl", ttl.String(),
		"pii_values_logged", false,
	)

	return vaultInst
}

// redactHomePath replaces the user's home directory prefix with "~" (Unix)
// or "%LOCALAPPDATA%" (Windows) to avoid logging usernames in filesystem paths.
// If the path does not start with a known home directory prefix, it is returned
// unchanged. The function never modifies the underlying string — it returns a
// new string if redaction is possible.
func redactHomePath(path string) string {
	// Windows: try %LOCALAPPDATA% first.
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		if after, ok := strings.CutPrefix(path, localAppData); ok {
			return "%LOCALAPPDATA%" + after
		}
	}
	// Unix (and Windows fallback): replace $HOME with "~".
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		if after, ok := strings.CutPrefix(path, homeDir); ok {
			return "~" + after
		}
	}
	return path
}

// initCA creates or loads the CA based on platform.
func initCA(cfg *policy.Config, logger *slog.Logger) (*qinduTls.CA, error) {
	caDir := getCADir()
	store := qinduTls.NewCAStore(caDir)
	return qinduTls.CreateOrLoadCA(store, cfg.TLS.CAName, cfg.TLS.CAValidityYears, logger)
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
