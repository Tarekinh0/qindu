package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
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
//   - CRL DP: file:///C:/ProgramData/Qindu/ca.crl (real CRL, schannel verified on disk)
//   - The certificate is NOT persisted to disk (memory only)
func GenerateLeafCert(ca *CA, host string) (*tls.Certificate, error) {
	// PR-002: nil guard — prevent panic if caller passes a nil CA
	if ca == nil {
		return nil, fmt.Errorf("GenerateLeafCert: CA must not be nil")
	}
	if ca.Cert == nil || ca.Key == nil {
		return nil, fmt.Errorf("GenerateLeafCert: CA certificate and key must not be nil")
	}

	// PR-003: validate hostname — trim whitespace and check structural validity
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("GenerateLeafCert: host must not be empty")
	}
	if !isValidHostname(host) {
		return nil, fmt.Errorf("GenerateLeafCert: invalid hostname %q", host)
	}

	// Generate ECDSA P-256 key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("GenerateLeafCert: generating key pair for %q: %w", host, err)
	}

	// Generate cryptographically random serial number (≥128 bits)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("GenerateLeafCert: generating serial for %q: %w", host, err)
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
		// BUG-004: CRL Distribution Point pointing to the real CA-generated CRL
		// file on disk. Windows schannel reads this CRL to verify the leaf cert
		// has not been revoked. Since the CRL is empty (no certs revoked), the
		// check passes. This replaces the dummy http://localhost URLs which
		// caused CRYPT_E_REVOCATION_OFFLINE (0x80092013).
		CRLDistributionPoints: []string{"file:///C:/ProgramData/Qindu/" + CRLFilename},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("GenerateLeafCert: creating certificate for %q: %w", host, err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("GenerateLeafCert: parsing DER for %q: %w", host, err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

// isValidHostname performs a lightweight structural validation of a DNS hostname.
// It rejects: empty strings, IP addresses, and names with characters outside the
// RFC 952/1123 allowed set (letters, digits, hyphens, dots). It does not perform
// DNS resolution.
func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	// Reject IP addresses — these should not be used as DNS names in certificates
	if net.ParseIP(host) != nil {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return false
	}
	// Reject labels that start or end with hyphen, and empty labels
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
