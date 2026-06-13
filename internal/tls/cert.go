package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// GenerateLeafCert creates a new ECDSA P-256 leaf certificate for the given hostname,
// signed by the CA. The certificate includes SAN entries for both the exact hostname
// and the wildcard subdomain (*.hostname).
//
// Security properties:
//   - Serial number generated with crypto/rand (≥128 bits entropy)
//   - ECDSA P-256 key pair generated with crypto/rand
//   - Certificate validity: 24 hours (regenerated on proxy restart)
//   - SAN: DNS:<host> + DNS:*.<host>
//   - The certificate is NOT persisted to disk (memory only)
func GenerateLeafCert(ca *CA, host string) (*tls.Certificate, error) {
	// Generate ECDSA P-256 key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate cryptographically random serial number (≥128 bits)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames: []string{
			host,
			"*." + host,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}
