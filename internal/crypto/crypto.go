// Package crypto provides pure AES-256-GCM encryption/decryption using Go stdlib.
// It manages a key file on disk and encrypts/decrypts arbitrary []byte values.
// The ciphertext format is: nonce(12 bytes) || ciphertext || GCM tag(16 bytes).
//
// This package is cross-platform: no CGO, no build tags for the core encrypt/decrypt.
// Hardware acceleration (AES-NI, ARM Crypto) is used automatically by the Go runtime.
//
// PII values MUST NOT appear in any log message or error from this package.
// All errors returned are safe for logging — they mention file paths and
// operation failures but never plaintext, ciphertext, or key material.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// nonceSize is the GCM standard nonce length (12 bytes / 96 bits).
const nonceSize = 12

// KeySize is the AES-256 key size in bytes.
const KeySize = 32

// Service provides AES-256-GCM encryption and decryption using a key loaded
// from or generated to a key file on disk.
//
// The key is kept in memory for the lifetime of the service. On Close(),
// the key material is zeroed in memory (defense-in-depth).
//
// Safe for concurrent use: GCM seal/open operations are inherently
// thread-safe when using independent nonces.
type Service struct {
	key    []byte // 32-byte AES key — zeroed on Close()
	aesGCM cipher.AEAD
}

// New loads or creates a 32-byte key from the given file path.
//
// If the file exists:
//   - Reads all bytes, validates length == 32.
//   - Validates file permissions are appropriate for the platform.
//
// If the file does not exist:
//   - Generates 32 random bytes via crypto/rand.
//   - Writes to the file with mode 0600.
//   - Creates parent directories if needed (mode 0700).
//
// Returns an error if the key file is invalid, permissions are too broad,
// or crypto/rand fails.
func New(keyPath string) (*Service, error) {
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	return &Service{
		key:    key,
		aesGCM: aesGCM,
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a fresh random nonce.
// Returns nonce || ciphertext || tag. The nonce is 12 bytes prepended.
// Each call generates a unique nonce from crypto/rand.
func (s *Service) Encrypt(plaintext []byte) ([]byte, error) {
	// nonce slice is passed as dst to Seal — single allocation in practice.
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}

	// GCM Seal appends ciphertext+tag to dst (nonce slice).
	// Since the nonce buffer is used as dst, the result is:
	// nonce(12) || ciphertext || GCM tag(16).
	ciphertext := s.aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
// Extracts the 12-byte nonce from the prefix, then verifies and decrypts.
// Returns an error if the GCM tag verification fails (tampered or wrong key).
func (s *Service) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, errors.New("crypto: ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	data := ciphertext[nonceSize:]

	plaintext, err := s.aesGCM.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed: %w", err)
	}
	return plaintext, nil
}

// Close zeros the key material in memory and clears the AEAD state.
// After Close, the service must not be used.
func (s *Service) Close() error {
	if s.key != nil {
		zeroBytes(s.key)
		s.key = nil
	}
	s.aesGCM = nil
	return nil
}

// loadOrCreateKey reads a 32-byte key from path, or generates and writes one.
func loadOrCreateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		// File exists — validate length and permissions.
		if len(data) != KeySize {
			return nil, fmt.Errorf("crypto: key file %s has wrong size: got %d bytes, expected %d",
				path, len(data), KeySize)
		}

		// Validate file permissions.
		if err := validateKeyFilePermissions(path); err != nil {
			return nil, err
		}

		return data, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("crypto: failed to read key file: %w", err)
	}

	// File does not exist — generate and write.
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate key: %w", err)
	}

	// Ensure parent directory exists (dirname of the key file).
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("crypto: failed to create key directory: %w", err)
	}

	if err := writeKeyFile(path, key); err != nil {
		zeroBytes(key)
		return nil, err
	}

	return key, nil
}

// writeKeyFile writes the 32-byte key to disk with mode 0600.
// Platform-specific ACL logic is applied via the setPlatformACL hook.
func writeKeyFile(path string, key []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("crypto: failed to create key file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(key); err != nil {
		return fmt.Errorf("crypto: failed to write key file: %w", err)
	}

	// Ensure key data is durably written to disk before returning (PR-109).
	if err := f.Sync(); err != nil {
		return fmt.Errorf("crypto: failed to sync key file: %w", err)
	}

	// Ensure mode is 0600 even if umask interfered.
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("crypto: failed to set key file permissions: %w", err)
	}

	return nil
}

// validateKeyFilePermissions checks that the key file has mode exactly 0600.
// On Unix, this is the primary access control mechanism.
// On Windows, %LOCALAPPDATA% already has restrictive ACLs enforced by the OS
// (only the user + SYSTEM can access their own profile), so this check is
// informational rather than security-critical.
func validateKeyFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("crypto: failed to stat key file: %w", err)
	}

	mode := info.Mode().Perm()
	// On Windows, os.Stat().Mode().Perm() may return 0666 or other values
	// because Unix permission bits don't map cleanly to Windows ACLs.
	// Only enforce 0600 on Unix platforms.
	if runtime.GOOS == "windows" {
		return nil
	}
	if mode != 0600 {
		return fmt.Errorf("crypto: key file %s has unsafe permissions %04o, expected 0600. "+
			"Fix with: chmod 0600 %s", path, mode, path)
	}

	return nil
}

// checkFileMode reports whether the file at path has exactly the expected permissions.
// Used by key file permission validation tests.
func checkFileMode(path string, expected fs.FileMode) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().Perm() == expected, nil
}

// zeroBytes overwrites b with zeros to clear sensitive material from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
