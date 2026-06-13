package tls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// TestGenerateLeafCert_SAN verifies SAN contains domain and wildcard.
func TestGenerateLeafCert_SAN(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "chatgpt.com")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	if cert.Leaf == nil {
		t.Fatal("Leaf certificate field should be populated")
	}

	// Verify SAN contains the domain
	foundExact := false
	foundWildcard := false
	for _, name := range cert.Leaf.DNSNames {
		if name == "chatgpt.com" {
			foundExact = true
		}
		if name == "*.chatgpt.com" {
			foundWildcard = true
		}
	}

	if !foundExact {
		t.Error("SAN should contain 'chatgpt.com'")
	}
	if !foundWildcard {
		t.Error("SAN should contain '*.chatgpt.com'")
	}
}

// TestGenerateLeafCert_Algorithm verifies leaf cert uses ECDSA P-256.
func TestGenerateLeafCert_Algorithm(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "test.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	if cert.Leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA, got %v", cert.Leaf.PublicKeyAlgorithm)
	}
}

// TestGenerateLeafCert_Validity verifies leaf cert has short validity (24h).
func TestGenerateLeafCert_Validity(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "test.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	validityDuration := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	// Should be approximately 24 hours
	if validityDuration < 23*3600*1e9 || validityDuration > 25*3600*1e9 {
		t.Errorf("expected ~24h validity, got %v", validityDuration)
	}
}

// TestGenerateLeafCert_SignedByCA verifies the leaf cert is signed by the CA.
func TestGenerateLeafCert_SignedByCA(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "test.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	// Verify the leaf certificate chain
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	opts := x509.VerifyOptions{
		DNSName: "test.ai",
		Roots:   roots,
	}
	if _, err := cert.Leaf.Verify(opts); err != nil {
		t.Errorf("leaf certificate verification failed: %v", err)
	}
}

// TestGenerateLeafCert_WildcardValidation verifies wildcard SAN works for verification.
func TestGenerateLeafCert_WildcardValidation(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "chatgpt.com")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	// Verify for subdomain (should work with wildcard)
	opts := x509.VerifyOptions{
		DNSName: "cdn.chatgpt.com",
		Roots:   roots,
	}
	if _, err := cert.Leaf.Verify(opts); err != nil {
		t.Errorf("wildcard verification for cdn.chatgpt.com failed: %v", err)
	}
}

// TestGenerateLeafCert_NotCA verifies leaf cert is not a CA.
func TestGenerateLeafCert_NotCA(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "test.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	if cert.Leaf.IsCA {
		t.Error("leaf certificate should not be a CA")
	}
}

// TestGenerateLeafCert_ServerAuth verifies leaf cert has ServerAuth EKU.
func TestGenerateLeafCert_ServerAuth(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "test.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	hasServerAuth := false
	for _, eku := range cert.Leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Error("leaf certificate should have ServerAuth extended key usage")
	}
}

// TestGenerateLeafCert_TLSCertFormat verifies the generated cert can be used in tls.Config.
func TestGenerateLeafCert_TLSCertFormat(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "test.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	// Verify it can be used in a TLS config
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	if cfg.Certificates[0].PrivateKey == nil {
		t.Error("certificate should have a private key")
	}
}

// TestGenerateLeafCert_UniqueSerialNumbers verifies each leaf cert has unique serial.
func TestGenerateLeafCert_UniqueSerialNumbers(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert1, err := GenerateLeafCert(ca, "test1.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert 1 failed: %v", err)
	}
	cert2, err := GenerateLeafCert(ca, "test2.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert 2 failed: %v", err)
	}

	if cert1.Leaf.SerialNumber.Cmp(cert2.Leaf.SerialNumber) == 0 {
		t.Error("leaf certs should have unique serial numbers")
	}
}
