package tls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGenerateLeafCert_SAN verifies SAN contains domain and wildcard.
func TestGenerateLeafCert_SAN(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1, nil)
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
	ca, _, err := GenerateCA("Test CA", 1, nil)
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
	ca, _, err := GenerateCA("Test CA", 1, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cert, err := GenerateLeafCert(ca, "test.ai")
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}

	validityDuration := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	// Should be approximately 24 hours
	if validityDuration < 23*time.Hour || validityDuration > 25*time.Hour {
		t.Errorf("expected ~24h validity, got %v", validityDuration)
	}
}

// TestGenerateLeafCert_SignedByCA verifies the leaf cert is signed by the CA.
func TestGenerateLeafCert_SignedByCA(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1, nil)
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
	ca, _, err := GenerateCA("Test CA", 1, nil)
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
	ca, _, err := GenerateCA("Test CA", 1, nil)
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
	ca, _, err := GenerateCA("Test CA", 1, nil)
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
	ca, _, err := GenerateCA("Test CA", 1, nil)
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
	ca, _, err := GenerateCA("Test CA", 1, nil)
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

// TestGenerateLeafCert_RevocationExtensions verifies that leaf certificates
// include a CRL Distribution Point extension pointing to the real CRL file
// on disk (BUG-004 fix). The OCSP (AIA) extension must NOT be present —
// Qindu uses CRL-only revocation, not OCSP.
func TestGenerateLeafCert_RevocationExtensions(t *testing.T) {
	ca, _, err := GenerateCA("Test CA", 1, nil)
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

	// OCSP must NOT be present — Qindu is CRL-only
	if len(cert.Leaf.OCSPServer) != 0 {
		t.Errorf("leaf cert should NOT have OCSP servers (CRL-only), got: %v", cert.Leaf.OCSPServer)
	}

	// Verify CRL Distribution Points contain the file:// URL
	if len(cert.Leaf.CRLDistributionPoints) == 0 {
		t.Error("leaf cert should have at least one CRL Distribution Point")
	}
	foundFileCRL := false
	expectedCDP := "file:///C:/ProgramData/Qindu/" + CRLFilename
	for _, url := range cert.Leaf.CRLDistributionPoints {
		if url == expectedCDP {
			foundFileCRL = true
			break
		}
	}
	if !foundFileCRL {
		t.Errorf("leaf cert CRL DP should contain %q, got: %v", expectedCDP, cert.Leaf.CRLDistributionPoints)
	}
}

// TestCreateCRL verifies that CreateCRL generates a valid, empty CRL
// signed by the CA. The CRL must contain no revoked certificates and
// must be parseable by Go's x509 library. This CRL is the real revocation
// mechanism that schannel verifies against the leaf cert's CDP.
func TestCreateCRL(t *testing.T) {
	ca, _, err := GenerateCA("Test CRL CA", 10, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	crlDER, err := CreateCRL(ca)
	if err != nil {
		t.Fatalf("CreateCRL failed: %v", err)
	}

	if len(crlDER) == 0 {
		t.Fatal("CRL DER bytes must not be empty")
	}

	// Parse the CRL back and verify its properties
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList failed: %v", err)
	}

	// Verify the CRL contains no revoked certificates
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("CRL should have 0 revoked certs, got %d", len(crl.RevokedCertificateEntries))
	}

	// Verify the CRL is signed by the CA
	err = crl.CheckSignatureFrom(ca.Cert)
	if err != nil {
		t.Errorf("CRL signature verification failed: %v", err)
	}

	// Verify CRL validity period
	if crl.ThisUpdate.IsZero() {
		t.Error("CRL ThisUpdate must not be zero")
	}
	if crl.NextUpdate.IsZero() {
		t.Error("CRL NextUpdate must not be zero")
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Error("CRL NextUpdate must be after ThisUpdate")
	}

	// Verify SaveCRL writes to disk and the file is readable
	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, CRLFilename)
	err = SaveCRL(crlDER, crlPath)
	if err != nil {
		t.Fatalf("SaveCRL failed: %v", err)
	}

	data, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) != len(crlDER) {
		t.Errorf("CRL file length mismatch: wrote %d bytes, read %d bytes", len(crlDER), len(data))
	}

	// Verify the file on disk is parseable (round-trip)
	if _, err := x509.ParseRevocationList(data); err != nil {
		t.Errorf("round-trip CRL parsing failed: %v", err)
	}
}
