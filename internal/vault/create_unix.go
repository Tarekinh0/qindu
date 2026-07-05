//go:build !windows

package vault

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/Tarekinh0/qindu/internal/crypto"
	"github.com/Tarekinh0/qindu/internal/session"
)

// createUserVault creates/opens a vault for the given user.
// On Unix, no impersonation is needed — the process runs as the user.
// token is ignored on this platform.
func createUserVault(resolved *session.ResolvedUser, ttl time.Duration, logger *slog.Logger, _ uintptr) (*Vault, error) {
	if err := os.MkdirAll(resolved.VaultPath, 0700); err != nil {
		return nil, fmt.Errorf("vault: cannot create vault directory: %w", err)
	}

	cryptoService, err := crypto.New(resolved.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("vault: crypto init failed: %w", err)
	}

	var vaultErr error
	defer func() {
		if vaultErr != nil {
			_ = cryptoService.Close()
		}
	}()

	db, err := bolt.Open(resolved.DBPath, 0600, &bolt.Options{
		Timeout: 1 * time.Second,
		NoSync:  false,
	})
	if err != nil {
		vaultErr = fmt.Errorf("vault: bolt open failed: %w", err)
		return nil, vaultErr
	}
	defer func() {
		if vaultErr != nil {
			_ = db.Close()
		}
	}()

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BucketTokens))
		return err
	}); err != nil {
		vaultErr = fmt.Errorf("vault: bucket creation failed: %w", err)
		return nil, vaultErr
	}

	v, err := New(db, cryptoService, ttl, logger)
	if err != nil {
		vaultErr = err
		return nil, vaultErr
	}

	v.Run(context.Background())
	return v, nil
}
