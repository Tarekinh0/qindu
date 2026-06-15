// Package tls provides CA management, certificate generation, and caching for Qindu MITM proxy.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CA represents the Qindu root Certificate Authority.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// CAStore defines the platform-specific CA storage operations.
type CAStore interface {
	// Save persists the encrypted CA key material.
	Save(certPEM, keyPEM []byte) error
	// Load retrieves the CA key material.
	Load() (*CA, error)
	// NeedsGeneration returns true if no stored CA exists.
	NeedsGeneration() bool
}

// CRLFilename is the standard filename for the Certificate Revocation List
// generated alongside the CA. Referenced by leaf cert CDP extensions and
// by the ca-init subcommand when persisting the CRL to disk.
const CRLFilename = "ca.crl"

// GenerateCA creates a new ECDSA P-256 CA certificate and key.
// The key is generated using crypto/rand (cryptographically secure PRNG).
// The certificate is self-signed with the given common name and validity period.
// If permittedDNSDomains is non-empty, the resulting CA certificate will include
// an X.509 Name Constraints extension (OID 2.5.29.30) restricting the CA to
// those DNS subtrees. The extension is marked non-critical for browser compatibility.
func GenerateCA(commonName string, validityYears int, permittedDNSDomains []string) (*CA, []byte, error) {
	// Generate ECDSA P-256 key pair using crypto/rand
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Generate serial number using crypto/rand (RFC 5280)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(validityYears, 0, 0)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // CA can only sign leaf certificates, not intermediate CAs
	}

	// Add Name Constraints if domains are specified (non-critical for compatibility).
	if len(permittedDNSDomains) > 0 {
		template.PermittedDNSDomains = permittedDNSDomains
		template.PermittedDNSDomainsCritical = false
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// PEM encode the private key
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	ca := &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
	}

	return ca, keyPEM, nil
}

// CACertPool returns a new x509.CertPool containing the CA certificate.
func (ca *CA) CACertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// CreateCRL generates an empty X.509 Certificate Revocation List signed by the CA.
// The CRL contains no revoked certificates (Qindu does not revoke leaf certs —
// they expire after 24 hours). It exists solely to provide a valid CRL Distribution
// Point that Windows schannel can verify, preventing CRYPT_E_REVOCATION_OFFLINE.
//
// The CRL validity matches the CA validity (10 years by default) and is marked
// with the same ECDSA P-256 signature algorithm as the CA certificate.
func CreateCRL(ca *CA) ([]byte, error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, fmt.Errorf("CreateCRL: CA must be fully initialized")
	}

	thisUpdate := time.Now()
	nextUpdate := ca.Cert.NotAfter

	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.Cert, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("CreateCRL: signing revocation list: %w", err)
	}

	return crlDER, nil
}

// SaveCRL writes a DER-encoded CRL to the given file path with restricted
// permissions (0600 — owner read/write only). The parent directory must
// already exist; callers should use os.MkdirAll before invoking SaveCRL.
// The path should be an absolute path to the file (e.g.,
// C:\ProgramData\Qindu\ca.crl on Windows).
func SaveCRL(crlDER []byte, path string) error {
	if err := os.WriteFile(path, crlDER, 0600); err != nil {
		return fmt.Errorf("SaveCRL: writing to %s: %w", path, err)
	}
	return nil
}
