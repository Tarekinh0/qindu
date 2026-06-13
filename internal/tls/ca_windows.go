//go:build windows

package tls

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	crypt32  = syscall.NewLazyDLL("crypt32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

// dataBlob is the Windows CRYPTOAPI_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// DPAPI protection flags.
const (
	cryptProtectUIFForbidden = 0x1 // CRYPTPROTECT_UI_FORBIDDEN
	cryptProtectLocalMachine = 0x4 // CRYPTPROTECT_LOCAL_MACHINE
)

// windowsCAStore implements CAStore using DPAPI-encrypted disk storage.
type windowsCAStore struct {
	caDir string
}

// NewCAStore creates a CAStore for Windows using DPAPI encryption.
func NewCAStore(caDir string) CAStore {
	return &windowsCAStore{caDir: caDir}
}

func (s *windowsCAStore) NeedsGeneration() bool {
	certPath := filepath.Join(s.caDir, "ca.crt")
	keyPath := filepath.Join(s.caDir, "ca.key")
	_, errCert := os.Stat(certPath)
	_, errKey := os.Stat(keyPath)
	return os.IsNotExist(errCert) || os.IsNotExist(errKey)
}

func (s *windowsCAStore) Save(certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(s.caDir, 0700); err != nil {
		return fmt.Errorf("creating CA directory: %w", err)
	}

	// Encrypt the private key using DPAPI before writing to disk
	encryptedKey, err := dpapiEncrypt(keyPEM)
	if err != nil {
		return fmt.Errorf("DPAPI encrypting CA key: %w", err)
	}

	certPath := filepath.Join(s.caDir, "ca.crt")
	keyPath := filepath.Join(s.caDir, "ca.key")

	// Write certificate (public, plaintext)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing CA certificate: %w", err)
	}

	// Write encrypted private key (DPAPI-encrypted blob)
	if err := os.WriteFile(keyPath, encryptedKey, 0600); err != nil {
		return fmt.Errorf("writing encrypted CA key: %w", err)
	}

	return nil
}

func (s *windowsCAStore) Load() (*CA, error) {
	certPath := filepath.Join(s.caDir, "ca.crt")
	keyPath := filepath.Join(s.caDir, "ca.key")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}

	encryptedKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading encrypted CA key: %w", err)
	}

	// Decrypt using DPAPI
	keyPEM, err := dpapiDecrypt(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("DPAPI decrypting CA key: %w", err)
	}

	return parseCAFromPEM(certPEM, keyPEM)
}

// dpapiEncrypt encrypts data using Windows DPAPI (CryptProtectData).
// Uses CRYPTPROTECT_LOCAL_MACHINE to bind encryption to the machine rather
// than the current user, so both console (admin) and service (SYSTEM) contexts
// can decrypt the key.
func dpapiEncrypt(data []byte) ([]byte, error) {
	var inBlob dataBlob
	if len(data) > 0 {
		inBlob.cbData = uint32(len(data))
		inBlob.pbData = &data[0]
	}

	var outBlob dataBlob

	flags := uint32(cryptProtectUIFForbidden | cryptProtectLocalMachine)

	r1, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		uintptr(0), // szDataDescr
		uintptr(0), // pOptionalEntropy
		uintptr(0), // pvReserved
		uintptr(0), // pPromptStruct
		uintptr(flags),
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	encrypted := make([]byte, outBlob.cbData)
	copy(encrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return encrypted, nil
}

// dpapiDecrypt decrypts data using Windows DPAPI (CryptUnprotectData).
// Must match the flags used during encryption (CRYPTPROTECT_LOCAL_MACHINE).
func dpapiDecrypt(data []byte) ([]byte, error) {
	var inBlob dataBlob
	if len(data) > 0 {
		inBlob.cbData = uint32(len(data))
		inBlob.pbData = &data[0]
	}

	var outBlob dataBlob
	var desc uintptr // description string, ignored

	flags := uint32(cryptProtectUIFForbidden | cryptProtectLocalMachine)

	r1, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		uintptr(unsafe.Pointer(&desc)),
		uintptr(0), // pOptionalEntropy
		uintptr(0), // pvReserved
		uintptr(0), // pPromptStruct
		uintptr(flags),
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return decrypted, nil
}
