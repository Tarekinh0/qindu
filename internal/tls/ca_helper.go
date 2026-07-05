package tls

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
)

var errNoStoredCA = errors.New("no stored CA found")

// CreateOrLoadCA handles CA initialization: loads existing or creates new.
// On Windows, the CA is stored encrypted via DPAPI on disk.
// On other platforms, the CA is kept in memory only.
//
// crlPath is the absolute path to the CRL file (e.g., C:\ProgramData\Qindu\ca.crl).
// It is stored in the CA struct and used by leaf certificate generation to embed
// a file:// CRL Distribution Point URL. If empty, no CRL DP is set.
func CreateOrLoadCA(store CAStore, commonName string, validityYears int, crlPath string, logger *slog.Logger) (*CA, error) {
	if !store.NeedsGeneration() {
		logger.Info("loading existing CA from storage")
		ca, err := store.Load()
		if err != nil {
			return nil, fmt.Errorf("loading existing CA: %w", err)
		}
		ca.CRLPath = crlPath
		logger.Info("CA loaded successfully",
			"subject", ca.Cert.Subject.CommonName,
			"expires", ca.Cert.NotAfter.Format("2006-01-02"),
		)
		return ca, nil
	}

	logger.Info("generating new CA",
		"common_name", commonName,
		"validity_years", validityYears,
		"algorithm", "ECDSA_P256",
	)

	ca, keyPEM, err := GenerateCA(commonName, validityYears, nil)
	if err != nil {
		return nil, fmt.Errorf("generating CA: %w", err)
	}

	ca.CRLPath = crlPath

	if err := store.Save(ca.CertPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("saving CA: %w", err)
	}

	logger.Info("CA generated and saved successfully",
		"subject", ca.Cert.Subject.CommonName,
		"expires", ca.Cert.NotAfter.Format("2006-01-02"),
		"serial", fmt.Sprintf("%X", ca.Cert.SerialNumber),
	)

	return ca, nil
}

// parseCAFromPEM parses PEM-encoded CA certificate and key.
func parseCAFromPEM(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse CA key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}

	// Verify key matches certificate (compare public keys)
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not ECDSA P-256 (got %T), file may be corrupted", cert.PublicKey)
	}
	if !certPub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("CA key does not match certificate")
	}

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
	}, nil
}
