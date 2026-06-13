//go:build !windows

package tls

// otherCAStore implements CAStore with memory-only storage.
// On non-Windows platforms (Linux, macOS, CI), the CA key is never persisted to disk.
type otherCAStore struct {
	ca     *CA
	keyPEM []byte
	hadCA  bool
}

// NewCAStore creates a CAStore for non-Windows platforms (memory only).
func NewCAStore(caDir string) CAStore {
	_ = caDir // unused on non-Windows
	return &otherCAStore{}
}

func (s *otherCAStore) NeedsGeneration() bool {
	return !s.hadCA
}

func (s *otherCAStore) Save(certPEM, keyPEM []byte) error {
	// On non-Windows, we keep CA in memory only.
	// Parse and store in memory.
	ca, err := parseCAFromPEM(certPEM, keyPEM)
	if err != nil {
		return err
	}
	s.ca = ca
	s.keyPEM = keyPEM
	s.hadCA = true
	return nil
}

func (s *otherCAStore) Load() (*CA, error) {
	if s.ca == nil {
		return nil, errNoStoredCA
	}
	return s.ca, nil
}
