package policy

import (
	"strings"
	"testing"
)

// TestGeneratePAC_ContainsDomains verifies the PAC script contains all AI domains.
func TestGeneratePAC_ContainsDomains(t *testing.T) {
	domains := []string{"chatgpt.com", "claude.ai"}
	proxyAddr := "127.0.0.1:8787"

	pac := GeneratePAC(domains, proxyAddr)

	// Verify all domains are present
	for _, d := range domains {
		if !strings.Contains(pac, `"`+d+`"`) {
			t.Errorf("PAC does not contain domain %q", d)
		}
	}

	// Verify proxy address is present
	if !strings.Contains(pac, proxyAddr) {
		t.Errorf("PAC does not contain proxy address %q", proxyAddr)
	}

	// Verify PAC structure
	if !strings.Contains(pac, "function FindProxyForURL") {
		t.Error("PAC does not contain FindProxyForURL function")
	}
	if !strings.Contains(pac, "PROXY") {
		t.Error("PAC does not contain PROXY directive")
	}
	if !strings.Contains(pac, "DIRECT") {
		t.Error("PAC does not contain DIRECT directive")
	}
	if !strings.Contains(pac, "dnsDomainIs") {
		t.Error("PAC does not contain dnsDomainIs function")
	}
	if !strings.Contains(pac, "shExpMatch") {
		t.Error("PAC does not contain shExpMatch function")
	}
}

// TestGeneratePAC_EmptyDomains verifies PAC generation works with no domains.
func TestGeneratePAC_EmptyDomains(t *testing.T) {
	domains := []string{}
	proxyAddr := "127.0.0.1:8787"

	pac := GeneratePAC(domains, proxyAddr)

	if !strings.Contains(pac, "function FindProxyForURL") {
		t.Error("PAC should still have FindProxyForURL function")
	}
	if !strings.Contains(pac, "DIRECT") {
		t.Error("PAC should contain DIRECT for empty domains")
	}
}

// TestGeneratePAC_SingleDomain verifies PAC generation with one domain.
func TestGeneratePAC_SingleDomain(t *testing.T) {
	domains := []string{"chatgpt.com"}
	proxyAddr := "127.0.0.1:8787"

	pac := GeneratePAC(domains, proxyAddr)

	if !strings.Contains(pac, `"chatgpt.com"`) {
		t.Error("PAC should contain chatgpt.com")
	}

	// Should not have trailing comma issues
	if strings.Contains(pac, ",]") {
		t.Error("PAC should not have trailing comma in array")
	}
}

// TestGeneratePAC_NoSecrets verifies SR10/SR12: PAC contains no secrets or identifiers.
func TestGeneratePAC_NoSecrets(t *testing.T) {
	domains := []string{"chatgpt.com"}
	proxyAddr := "127.0.0.1:8787"

	pac := GeneratePAC(domains, proxyAddr)

	// Must not contain sensitive data
	forbidden := []string{
		"private key",
		"PRIVATE KEY",
		"CERTIFICATE",
		"password",
		"secret",
		"token",
		"api_key",
		"Set-Cookie",
		"uuid",
		"machineid",
		"fingerprint",
	}

	for _, f := range forbidden {
		if strings.Contains(strings.ToLower(pac), strings.ToLower(f)) {
			t.Errorf("PAC contains forbidden content: %q", f)
		}
	}
}

// TestGeneratePAC_ProxyAddrFormat verifies proxy address formatting.
func TestGeneratePAC_ProxyAddrFormat(t *testing.T) {
	domains := []string{"test.ai"}
	proxyAddr := "127.0.0.1:9999"

	pac := GeneratePAC(domains, proxyAddr)

	expected := `PROXY ` + proxyAddr
	if !strings.Contains(pac, expected) {
		t.Errorf("PAC should contain %q", expected)
	}
}
