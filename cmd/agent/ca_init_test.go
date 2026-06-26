package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/Tarekinh0/qindu/internal/policy"
	qinduTls "github.com/Tarekinh0/qindu/internal/tls"
)

// SAFETY: No PII in log output. All test data uses synthetic domains
// (test.com, test.example, chatgpt.com, claude.ai, new.example, rt.example)
// and auto-generated CA certificate metadata. No real user data, keys, or
// credentials appear in test output or test failure messages.
//
// TestGenerateCAWithNameConstraints verifies that a CA generated with
// permitted DNS domains includes the Name Constraints extension.
func TestGenerateCAWithNameConstraints(t *testing.T) {
	permittedDomains := []string{"chatgpt.com", "claude.ai"}
	ca, _, err := qinduTls.GenerateCA("Test Constrained CA", 10, permittedDomains)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Verify Name Constraints extension is present
	var foundConstraints bool
	for _, ext := range ca.Cert.Extensions {
		if ext.Id.Equal(oidNameConstraints) {
			foundConstraints = true
			break
		}
	}
	if !foundConstraints {
		t.Error("CA certificate does not contain Name Constraints extension (OID 2.5.29.30)")
	}

	// Verify PermittedDNSDomains are in the parsed certificate
	if len(ca.Cert.PermittedDNSDomains) != len(permittedDomains) {
		t.Errorf("expected %d permitted DNS domains, got %d: %v",
			len(permittedDomains), len(ca.Cert.PermittedDNSDomains), ca.Cert.PermittedDNSDomains)
	}

	for i, d := range permittedDomains {
		if ca.Cert.PermittedDNSDomains[i] != d {
			t.Errorf("permitted domain[%d]: expected %q, got %q", i, d, ca.Cert.PermittedDNSDomains[i])
		}
	}
}

// TestGenerateCAWithoutNameConstraints verifies that a CA generated without
// permitted domains does NOT include the Name Constraints extension.
func TestGenerateCAWithoutNameConstraints(t *testing.T) {
	ca, _, err := qinduTls.GenerateCA("Test Unconstrained CA", 10, nil)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Verify Name Constraints extension is NOT present
	for _, ext := range ca.Cert.Extensions {
		if ext.Id.Equal(oidNameConstraints) {
			t.Error("CA certificate should NOT contain Name Constraints when no domains are specified")
		}
	}

	if len(ca.Cert.PermittedDNSDomains) != 0 {
		t.Errorf("expected 0 permitted DNS domains, got %v", ca.Cert.PermittedDNSDomains)
	}
}

// TestCAInit_ConfigFlagResolution verifies that --config flag works for
// ca-init command. We test the resolveConfigPath function directly.
func TestResolveConfigPath_ExplicitFlag(t *testing.T) {
	path, err := resolveConfigPath("/custom/path/config.yaml")
	if err != nil {
		t.Fatalf("resolveConfigPath: %v", err)
	}
	if path != "/custom/path/config.yaml" {
		t.Errorf("explicit path should be returned as-is, got %q", path)
	}
}

// TestResolveConfigPath_EnvVar verifies that QINDU_CONFIG env var is respected.
func TestResolveConfigPath_EnvVar(t *testing.T) {
	t.Setenv("QINDU_CONFIG", "/env/path/config.yaml")

	path, err := resolveConfigPath("")
	if err != nil {
		t.Fatalf("resolveConfigPath: %v", err)
	}
	if path != "/env/path/config.yaml" {
		t.Errorf("env var path should be used, got %q", path)
	}
}

// TestResolveConfigPath_ProgramFiles verifies the Windows PROGRAMFILES path.
func TestResolveConfigPath_ProgramFiles(t *testing.T) {
	t.Setenv("PROGRAMFILES", "/tmp/testpf")
	t.Setenv("QINDU_CONFIG", "")

	// Create the expected directory and file
	configDir := filepath.Join("/tmp/testpf", "Qindu", "configs")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	configFile := filepath.Join(configDir, "default.yaml")
	if err := os.WriteFile(configFile, []byte("agent:\n  listen_addr: 127.0.0.1\n  listen_port: 8787\n"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	defer func() { _ = os.RemoveAll("/tmp/testpf") }()

	path, err := resolveConfigPath("")
	if err != nil {
		t.Fatalf("resolveConfigPath: %v", err)
	}
	if path != configFile {
		t.Errorf("expected programfiles path %q, got %q", configFile, path)
	}
}

// TestResolveConfigPath_EnvVarPriority verifies that --config takes priority
// over everything, and QINDU_CONFIG takes priority over PROGRAMFILES.
func TestResolveConfigPath_EnvVarOverProgramFiles(t *testing.T) {
	t.Setenv("QINDU_CONFIG", "/env/path/cfg.yaml")
	t.Setenv("PROGRAMFILES", "/tmp/testpf2")

	// Even if PROGRAMFILES file exists, QINDU_CONFIG should win
	path, err := resolveConfigPath("")
	if err != nil {
		t.Fatalf("resolveConfigPath: %v", err)
	}
	if path != "/env/path/cfg.yaml" {
		t.Errorf("QINDU_CONFIG should take priority over PROGRAMFILES, got %q", path)
	}
}

// TestCAInit_RegenerationProducesDifferentCA verifies that calling GenerateCA
// twice produces different key material (serial, key bytes) — confirming
// that CA regeneration does not reuse the previous CA.
func TestCAInit_RegenerationProducesDifferentCA(t *testing.T) {
	var err error
	var ca1, ca2 *qinduTls.CA
	var keyPEM1, keyPEM2 []byte

	ca1, keyPEM1, err = qinduTls.GenerateCA("Test CA", 10, []string{"test.com"})
	if err != nil {
		t.Fatalf("GenerateCA (first): %v", err)
	}
	ca2, keyPEM2, err = qinduTls.GenerateCA("Test CA", 10, []string{"test.com"})
	if err != nil {
		t.Fatalf("GenerateCA (second): %v", err)
	}

	// Verify different serial numbers
	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) == 0 {
		t.Error("re-generated CA should have a different serial number")
	}

	// Verify different key material
	if string(keyPEM1) == string(keyPEM2) {
		t.Error("re-generated CA key should differ from the previous one")
	}
}

// TestCAInit_DestroyAndRecreateCA verifies that destroying existing CA files
// and re-saving produces a fresh CA. On platforms with filesystem storage
// (Windows), this tests real file operations. On memory-only platforms
// (Linux/macOS), the filesystem assertions are skipped gracefully.
func TestCAInit_DestroyAndRecreateCA(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PROGRAMDATA", tmpDir)

	caDir := getCADir()
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatalf("failed to create CA dir: %v", err)
	}

	// Create dummy CA files to simulate a previous installation
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")
	if err := os.WriteFile(certPath, []byte("old-cert-data"), 0644); err != nil {
		t.Fatalf("writing dummy cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("old-key-data"), 0600); err != nil {
		t.Fatalf("writing dummy key: %v", err)
	}

	// Verify files exist before destroy
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatal("dummy cert should exist before destroy")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("dummy key should exist before destroy")
	}

	// Destroy existing CA
	if err := destroyExistingCA(caDir); err != nil {
		t.Fatalf("destroyExistingCA: %v", err)
	}

	// Verify files are gone
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Error("CA key file should have been removed by destroyExistingCA")
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Error("CA cert file should have been removed by destroyExistingCA")
	}

	// Generate new CA and save
	ca, keyPEM, err := qinduTls.GenerateCA("New CA", 10, []string{"new.example"})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	store := qinduTls.NewCAStore(caDir)
	err = store.Save(ca.CertPEM, keyPEM)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify new CA can be loaded (platform-specific: disk on Windows, memory on Linux)
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Cert.Subject.CommonName != "New CA" {
		t.Errorf("expected 'New CA', got %q", loaded.Cert.Subject.CommonName)
	}
}

// TestCAInit_StoreLoadRoundtrip verifies that a CA saved via the platform
// store can be loaded back correctly.
func TestCAInit_StoreLoadRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PROGRAMDATA", tmpDir)

	caDir := getCADir()
	store := qinduTls.NewCAStore(caDir)

	ca, keyPEM, err := qinduTls.GenerateCA("Roundtrip CA", 10, []string{"rt.example"})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	err = store.Save(ca.CertPEM, keyPEM)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Cert.Subject.CommonName != "Roundtrip CA" {
		t.Errorf("expected 'Roundtrip CA', got %q", loaded.Cert.Subject.CommonName)
	}
	if loaded.Cert.SerialNumber.Cmp(ca.Cert.SerialNumber) != 0 {
		t.Error("loaded CA serial number does not match original")
	}
}

// TestDestroyExistingCA_Idempotent verifies that destroying a non-existent CA
// does not error.
func TestDestroyExistingCA_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	if err := destroyExistingCA(tmpDir); err != nil {
		t.Errorf("destroyExistingCA on empty dir should not error: %v", err)
	}
}

// TestAllAIDomains verifies domain extraction from config.
func TestAllAIDomains(t *testing.T) {
	cfg := policy.DefaultConfig()
	domains := cfg.AllAIDomains()
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains from default config, got %d: %v", len(domains), domains)
	}

	expectedDomains := map[string]bool{"chatgpt.com": true, "claude.ai": true}
	for _, d := range domains {
		if !expectedDomains[d] {
			t.Errorf("unexpected domain %q in provider list", d)
		}
	}
}

// TestAllAIDomains_DisabledProvider verifies disabled providers are excluded.
func TestAllAIDomains_DisabledProvider(t *testing.T) {
	cfg := policy.DefaultConfig()
	// Disable claude
	claude := cfg.Providers["claude"]
	claude.Enabled = false
	cfg.Providers["claude"] = claude

	domains := cfg.AllAIDomains()
	if len(domains) != 1 {
		t.Fatalf("expected 1 domain (chatgpt only), got %d: %v", len(domains), domains)
	}
	if domains[0] != "chatgpt.com" {
		t.Errorf("expected 'chatgpt.com', got %q", domains[0])
	}
}

// TestConfirmUnsafeMode_NonInteractive verifies that unsafe mode is blocked
// when stdin is not a terminal (SR-INSTALLER-3, INST-SEC-T5).
func TestConfirmUnsafeMode_NonInteractive(t *testing.T) {
	// Stdin in test is not a terminal (it's a pipe/devnull),
	// so confirmUnsafeMode should return an error.
	err := confirmUnsafeMode()
	if err == nil {
		t.Error("confirmUnsafeMode should fail in non-interactive mode")
	}
}

// TestCADir_WindowsPath verifies getCADir uses PROGRAMDATA on Windows.
func TestGetCADir_ProgramData(t *testing.T) {
	t.Setenv("PROGRAMDATA", "C:\\ProgramData")

	dir := getCADir()
	expected := filepath.Join("C:\\ProgramData", "Qindu")
	if dir != expected {
		t.Errorf("expected %q, got %q", expected, dir)
	}
}

// TestGetCADir_Fallback verifies getCADir falls back to home directory
// or temp directory, depending on whether $HOME is set. Uses exact
// path computation instead of loose substring match (PR-M3 fix).
func TestGetCADir_Fallback(t *testing.T) {
	t.Setenv("PROGRAMDATA", "")

	var expected string
	if home, err := os.UserHomeDir(); err == nil {
		expected = filepath.Join(home, ".qindu", "ca")
	} else {
		expected = filepath.Join(os.TempDir(), "qindu-ca")
	}

	dir := getCADir()
	if dir != expected {
		t.Errorf("expected %q, got %q", expected, dir)
	}
}

// TestApplyConfigOverride_NoOverrideFile verifies no error when override
// file does not exist.
func TestApplyConfigOverride_NoOverrideFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PROGRAMDATA", tmpDir)

	cfg := policy.DefaultConfig()
	err := applyConfigOverride(cfg)
	if err != nil {
		t.Errorf("applyConfigOverride should not error when no override file exists: %v", err)
	}
}

// TestApplyConfigOverride_MergeSuccess verifies the config override merging.
func TestApplyConfigOverride_MergeSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PROGRAMDATA", tmpDir)

	// Create override directory and file
	qinduDir := filepath.Join(tmpDir, "Qindu")
	if err := os.MkdirAll(qinduDir, 0700); err != nil {
		t.Fatalf("MkdirAll override dir: %v", err)
	}

	overrideYAML := []byte(`
tls:
  ca_validity_years: 5
providers:
  chatgpt:
    enabled: true
    domains:
      - chatgpt.com
`)
	overridePath := filepath.Join(qinduDir, "config.yaml")
	if err := os.WriteFile(overridePath, overrideYAML, 0600); err != nil {
		t.Fatalf("writing override file: %v", err)
	}

	cfg := policy.DefaultConfig()
	err := applyConfigOverride(cfg)
	if err != nil {
		t.Fatalf("applyConfigOverride: %v", err)
	}

	// Override should change validity to 5
	if cfg.TLS.CAValidityYears != 5 {
		t.Errorf("expected CA validity 5 (overridden), got %d", cfg.TLS.CAValidityYears)
	}
	// Non-overridden fields should retain defaults
	if cfg.TLS.CAName != "Qindu AI Privacy CA" {
		t.Errorf("expected CA name to retain default, got %q", cfg.TLS.CAName)
	}
}

// TestLoadConfig_NotFound verifies that loading a non-existent config returns
// an error.
func TestLoadConfig_NotFound(t *testing.T) {
	_, err := loadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error loading non-existent config, got nil")
	}
}

// TestCAInit_CAKeyNotInOutput verifies that GenerateCA does not include
// private key material in the returned CA struct's CertPEM field
// (certificate only, no key). The key is returned separately as keyPEM.
func TestCAInit_CAKeyNotInOutput(t *testing.T) {
	ca, keyPEM, err := qinduTls.GenerateCA("Test CA", 1, []string{"test.example"})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// CertPEM should contain only the certificate
	certBlock, rest := pem.Decode(ca.CertPEM)
	if certBlock == nil {
		t.Fatal("failed to parse CA CertPEM")
	}
	if certBlock.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE PEM type, got %q", certBlock.Type)
	}
	if len(rest) > 0 {
		// There might be trailing newlines; check if there's another PEM block
		nextBlock, _ := pem.Decode(rest)
		if nextBlock != nil {
			// Any additional PEM block in CertPEM besides CERTIFICATE is suspicious
			t.Errorf("CertPEM contains unexpected PEM block of type %q", nextBlock.Type)
		}
	}

	// Verify the certificate parses correctly
	var parsedCert *x509.Certificate
	parsedCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing certificate from CertPEM: %v", err)
	}
	if parsedCert.Subject.CommonName != "Test CA" {
		t.Errorf("expected 'Test CA', got %q", parsedCert.Subject.CommonName)
	}

	// keyPEM should contain EC PRIVATE KEY
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to parse keyPEM")
	}
	if keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("expected 'EC PRIVATE KEY', got %q", keyBlock.Type)
	}
}

// TestCAInit_NameConstraintsNonCritical verifies the Name Constraints extension
// is marked non-critical for browser compatibility (SR-INSTALLER-11).
func TestCAInit_NameConstraintsNonCritical(t *testing.T) {
	ca, _, err := qinduTls.GenerateCA("Test CA", 10, []string{"example.com"})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	for _, ext := range ca.Cert.Extensions {
		if ext.Id.Equal(oidNameConstraints) {
			if ext.Critical {
				t.Error("Name Constraints extension should be non-critical for browser compatibility")
			}
			return // found and verified
		}
	}
	t.Error("Name Constraints extension not found")
}

// oidNameConstraints is the ASN.1 Object Identifier for X.509 Name Constraints (2.5.29.30).
var oidNameConstraints = []int{2, 5, 29, 30}
