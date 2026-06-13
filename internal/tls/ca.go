// Package tls provides CA management, certificate generation, and caching for Qindu MITM proxy.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

// GenerateCA creates a new ECDSA P-256 CA certificate and key.
// The key is generated using crypto/rand (cryptographically secure PRNG).
// The certificate is self-signed with the given common name and validity period.
func GenerateCA(commonName string, validityYears int) (*CA, []byte, error) {
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
		MaxPathLenZero:        true,
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
