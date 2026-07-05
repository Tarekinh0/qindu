//go:build windows

package vault

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/windows"

	"github.com/Tarekinh0/qindu/internal/crypto"
	"github.com/Tarekinh0/qindu/internal/session"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	// ImpersonateLoggedOnUser is not exported by golang.org/x/sys/windows v0.46.0,
	// so we define the proc directly.
	procImpersonateLoggedOnUser = modadvapi32.NewProc("ImpersonateLoggedOnUser")
)

// createUserVault performs filesystem operations to create/open a vault
// for the given user. On Windows service mode with a non-zero token,
// impersonation is used to gain write access to the user's profile.
// On console mode (zero token), no impersonation is needed.
//
// The impersonation scope is strictly limited to filesystem operations
// inside this function. defer RevertToSelf() guarantees the thread
// token is restored before ANY other code executes.
func createUserVault(resolved *session.ResolvedUser, ttl time.Duration, logger *slog.Logger, token uintptr) (*Vault, error) {
	// Impersonate if we have a token (service mode).
	if token != 0 {
		r1, _, e1 := syscall.SyscallN(procImpersonateLoggedOnUser.Addr(), token)
		if r1 == 0 {
			return nil, fmt.Errorf("vault: impersonation failed: %w", e1)
		}
		defer windows.RevertToSelf() // CRITICAL: must fire before ANY non-filesystem code
	}

	// ── ALL CODE BELOW RUNS AS THE USER (or service if no token) ──

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
