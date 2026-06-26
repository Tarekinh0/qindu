package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TestGenerateCA_ECDSA_P256 verifies that the CA is generated with ECDSA P-256.
func TestGenerateCA_ECDSA_P256(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Verify algorithm
	if ca.Cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA algorithm, got %v", ca.Cert.PublicKeyAlgorithm)
	}

	// Verify curve is P-256
	pubKey, ok := ca.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key is not ECDSA")
	}
	if pubKey.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", pubKey.Params().Name)
	}
}

// TestGenerateCA_Validity verifies CA validity period.
func TestGenerateCA_Validity(t *testing.T) {
	validityYears := 10
	ca, _, err := GenerateCA("Test CA", validityYears, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	expectedNotAfter := ca.Cert.NotBefore.AddDate(validityYears, 0, 0)
	// Allow 1-day tolerance for timing
	diff := ca.Cert.NotAfter.Sub(expectedNotAfter)
	if diff < -24*3600*1e9 || diff > 24*3600*1e9 {
		t.Errorf("validity period mismatch: notAfter=%v, expected ~%v",
			ca.Cert.NotAfter, expectedNotAfter)
	}
}

// TestGenerateCA_SerialNumber verifies serial number is generated with crypto/rand.
func TestGenerateCA_SerialNumber(t *testing.T) {
	// Generate two CAs and verify serial numbers are different
	ca1, _, err := GenerateCA("CA 1", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA 1 failed: %v", err)
	}
	ca2, _, err := GenerateCA("CA 2", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA 2 failed: %v", err)
	}

	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) == 0 {
		t.Error("two CAs should have different serial numbers")
	}

	// Verify serial number has sufficient entropy (at least 64 bits)
	if ca1.Cert.SerialNumber.BitLen() < 64 {
		t.Errorf("serial number has insufficient entropy: %d bits", ca1.Cert.SerialNumber.BitLen())
	}
}

// TestGenerateCA_IsCA verifies CA certificate properties.
func TestGenerateCA_IsCA(t *testing.T) {
	ca, _, err := GenerateCA("Root CA", 5, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if !ca.Cert.IsCA {
		t.Error("CA certificate should have IsCA = true")
	}
	if !ca.Cert.BasicConstraintsValid {
		t.Error("CA certificate should have BasicConstraintsValid = true")
	}
	if ca.Cert.MaxPathLen != 0 {
		t.Errorf("expected MaxPathLen=0 (path length constrained), got %d", ca.Cert.MaxPathLen)
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA certificate should have CertSign key usage")
	}
}

// TestGenerateCA_CertPEM verifies certificate PEM output is valid.
func TestGenerateCA_CertPEM(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if len(ca.CertPEM) == 0 {
		t.Error("CertPEM should not be empty")
	}

	// Verify it can be parsed back
	pool := ca.CACertPool()
	if pool == nil {
		t.Error("CACertPool should not be nil")
	}
}

// TestGenerateCA_SelfSigned verifies the CA is self-signed (Issuer == Subject).
func TestGenerateCA_SelfSigned(t *testing.T) {
	ca, _, err := GenerateCA("Self CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if ca.Cert.Issuer.CommonName != ca.Cert.Subject.CommonName {
		t.Errorf("self-signed CA issuer %q != subject %q",
			ca.Cert.Issuer.CommonName, ca.Cert.Subject.CommonName)
	}

	// Verify the certificate can be verified against itself
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := ca.Cert.Verify(opts); err != nil {
		t.Errorf("CA certificate self-verification failed: %v", err)
	}
}

// TestGenerateCA_KeyStrength verifies key strength.
func TestGenerateCA_KeyStrength(t *testing.T) {
	ca, _, err := GenerateCA("Strong CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if ca.Key.Curve != elliptic.P256() {
		t.Error("key must use P-256 curve")
	}

	if ca.Key.Params().BitSize != 256 {
		t.Errorf("expected 256-bit key, got %d bits", ca.Key.Params().BitSize)
	}
}

// TestParseCAFromPEM verifies round-trip PEM encoding/decoding.
func TestParseCAFromPEM(t *testing.T) {
	ca, keyPEM, err := GenerateCA("Roundtrip CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	parsed, err := parseCAFromPEM(ca.CertPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCAFromPEM failed: %v", err)
	}

	if parsed.Cert.SerialNumber.Cmp(ca.Cert.SerialNumber) != 0 {
		t.Error("round-trip CA serial number mismatch")
	}
	if parsed.Cert.Subject.CommonName != ca.Cert.Subject.CommonName {
		t.Error("round-trip CA common name mismatch")
	}
}

// TestParseCAFromPEM_InvalidInput verifies error handling for bad PEM.
func TestParseCAFromPEM_InvalidInput(t *testing.T) {
	_, err := parseCAFromPEM([]byte("not valid pem"), []byte("also not valid"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// TestParseCAFromPEM_KeyMismatch verifies detection of key mismatch.
func TestParseCAFromPEM_KeyMismatch(t *testing.T) {
	ca1, _, err := GenerateCA("CA 1", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM2, err := GenerateCA("CA 2", 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Try to load cert from CA1 with key from CA2 (should fail)
	_, err = parseCAFromPEM(ca1.CertPEM, keyPEM2)
	if err == nil {
		t.Error("expected error for key/cert mismatch")
	}
}

// TestParseCAFromPEM_NonECDSAKey verifies that parseCAFromPEM returns a
// graceful error (not a panic) when the CA certificate contains a non-ECDSA
// public key (e.g., RSA). This is PR-001 / SEC-F4: bare type assertion fix.
func TestParseCAFromPEM_NonECDSAKey(t *testing.T) {
	// Generate an RSA key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	// Create a self-signed RSA certificate
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "RSA Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Marshal RSA private key to PEM
	keyDER := x509.MarshalPKCS1PrivateKey(rsaKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})

	// parseCAFromPEM should return an error, NOT panic
	_, err = parseCAFromPEM(certPEM, keyPEM)
	if err == nil {
		t.Error("expected error for non-ECDSA CA key (RSA), got nil")
	}
}
