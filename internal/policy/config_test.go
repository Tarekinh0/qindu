package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseConfig_ValidYAML verifies that a valid YAML config is parsed correctly.
func TestParseConfig_ValidYAML(t *testing.T) {
	yamlData := []byte(`
agent:
  listen_addr: "127.0.0.1"
  listen_port: 8787
  mode: "enforce"
  fail_mode: "fail_closed"

tls:
  ca_name: "Test CA"
  ca_validity_years: 10
  ca_key_algorithm: "ECDSA_P256"
  cert_cache_enabled: true
  upstream_validation: "system"

providers:
  chatgpt:
    enabled: true
    domains:
      - "chatgpt.com"
  claude:
    enabled: false
    domains:
      - "claude.ai"

logging:
  level: "info"
  format: "json"
  pii_logging: false
`)

	cfg, err := ParseConfig(yamlData)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if cfg.Agent.ListenAddr != "127.0.0.1" {
		t.Errorf("expected listen_addr 127.0.0.1, got %s", cfg.Agent.ListenAddr)
	}
	if cfg.Agent.ListenPort != 8787 {
		t.Errorf("expected listen_port 8787, got %d", cfg.Agent.ListenPort)
	}
	if cfg.TLS.CAName != "Test CA" {
		t.Errorf("expected ca_name 'Test CA', got %s", cfg.TLS.CAName)
	}
	if cfg.TLS.CAValidityYears != 10 {
		t.Errorf("expected ca_validity_years 10, got %d", cfg.TLS.CAValidityYears)
	}
	if cfg.TLS.UpstreamValidation != "system" {
		t.Errorf("expected upstream_validation 'system', got %s", cfg.TLS.UpstreamValidation)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected logging level 'info', got %s", cfg.Logging.Level)
	}

	// Check providers
	chatgpt, ok := cfg.Providers["chatgpt"]
	if !ok {
		t.Fatal("expected chatgpt provider")
	}
	if !chatgpt.Enabled {
		t.Error("expected chatgpt to be enabled")
	}
	if len(chatgpt.Domains) != 1 || chatgpt.Domains[0] != "chatgpt.com" {
		t.Errorf("unexpected chatgpt domains: %v", chatgpt.Domains)
	}

	claude, ok := cfg.Providers["claude"]
	if !ok {
		t.Fatal("expected claude provider")
	}
	if claude.Enabled {
		t.Error("expected claude to be disabled")
	}
}

// TestParseConfig_InvalidYAML verifies that invalid YAML returns an error.
func TestParseConfig_InvalidYAML(t *testing.T) {
	invalidYAML := []byte(`this is not valid: [yaml: definitely:`)

	_, err := ParseConfig(invalidYAML)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// TestParseConfig_EmptyYAML verifies that empty YAML is rejected by validation
// (ParseConfig now validates internally).
func TestParseConfig_EmptyYAML(t *testing.T) {
	emptyYAML := []byte(``)

	cfg, err := ParseConfig(emptyYAML)
	if err == nil {
		t.Error("expected validation error for empty config, got nil")
	}
	if cfg != nil {
		t.Error("expected nil config on error")
	}
}

// TestValidate_NonLoopbackBind verifies SR4: reject non-loopback addresses.
func TestValidate_NonLoopbackBind(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"loopback 127.0.0.1", "127.0.0.1", false},
		{"loopback ::1", "::1", false},
		{"non-loopback 0.0.0.0", "0.0.0.0", true},
		{"non-loopback 192.168.1.1", "192.168.1.1", true},
		{"non-loopback empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Agent.ListenAddr = tt.addr
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidate_UpstreamValidation verifies SR3: only "system" or "insecure" allowed.
func TestValidate_UpstreamValidation(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		wantErr bool
	}{
		{"valid system", "system", false},
		{"valid insecure", "insecure", false},
		{"invalid empty", "", true},
		{"invalid random", "none", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TLS.UpstreamValidation = tt.val
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidate_PortRange verifies port validation.
func TestValidate_PortRange(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid port 8787", 8787, false},
		{"valid port 80", 80, false},
		{"invalid port 0", 0, true},
		{"invalid port -1", -1, true},
		{"invalid port 99999", 99999, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Agent.ListenPort = tt.port
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidate_CAValidity verifies CA validity years must be positive.
func TestValidate_CAValidity(t *testing.T) {
	tests := []struct {
		name    string
		years   int
		wantErr bool
	}{
		{"valid 10 years", 10, false},
		{"invalid 0 years", 0, true},
		{"invalid negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TLS.CAValidityYears = tt.years
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidate_CAKeyAlgorithm verifies only ECDSA_P256 is allowed.
func TestValidate_CAKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"valid ECDSA_P256", "ECDSA_P256", false},
		{"invalid RSA", "RSA", true},
		{"invalid empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TLS.CAKeyAlgorithm = tt.algorithm
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestAllAIDomains verifies that only enabled provider domains are returned.
func TestAllAIDomains(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Providers = ProvidersConfig{
		"chatgpt": {Enabled: true, Domains: []string{"chatgpt.com", "openai.com"}},
		"claude":  {Enabled: false, Domains: []string{"claude.ai"}},
		"gemini":  {Enabled: true, Domains: []string{"gemini.google.com"}},
	}

	domains := cfg.AllAIDomains()

	// Build a set for order-independent comparison
	domainSet := make(map[string]bool)
	for _, d := range domains {
		domainSet[d] = true
	}

	expected := map[string]bool{
		"chatgpt.com":       true,
		"openai.com":        true,
		"gemini.google.com": true,
	}

	if len(domains) != len(expected) {
		t.Errorf("expected %d domains, got %d: %v", len(expected), len(domains), domains)
	}

	for exp := range expected {
		if !domainSet[exp] {
			t.Errorf("expected domain %q not found in result", exp)
		}
	}

	for d := range domainSet {
		if !expected[d] {
			t.Errorf("unexpected domain %q in result", d)
		}
	}
}

// TestDefaultConfig verifies the default config has correct values.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
	if cfg.Agent.ListenAddr != "127.0.0.1" {
		t.Error("default listen_addr must be 127.0.0.1")
	}
	if cfg.TLS.UpstreamValidation != "system" {
		t.Error("default upstream_validation must be 'system'")
	}
}

// TestValidate_AgentMode verifies SR-11: agent.mode must be one of transparent, monitor, enforce.
func TestValidate_AgentMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"valid transparent", "transparent", false},
		{"valid monitor", "monitor", false},
		{"valid enforce", "enforce", false},
		{"invalid empty", "", true},
		{"invalid detect", "detect", true},
		{"invalid random", "block", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Agent.Mode = tt.mode
			// For enforce mode, reset fail_mode to nil (defaults to fail_closed).
			if tt.mode == "enforce" {
				cfg.Agent.FailMode = nil
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestMergeFileOverride_ProvidersPreserved verifies PR-002:
// Merging an override that only specifies one provider must not delete
// other providers already present in the base config.
func TestMergeFileOverride_ProvidersPreserved(t *testing.T) {
	// Create a base config with two providers
	cfg := DefaultConfig()
	cfg.Providers = ProvidersConfig{
		"chatgpt": {Enabled: true, Domains: []string{"chatgpt.com"}},
		"claude":  {Enabled: true, Domains: []string{"claude.ai"}},
	}

	// Write an override file that only mentions chatgpt with different domains
	tmpDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "override.yaml")
	overrideYAML := []byte(`
providers:
  chatgpt:
    enabled: true
    domains:
      - "chatgpt.com"
      - "openai.com"
`)
	if err := os.WriteFile(overridePath, overrideYAML, 0644); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	// Merge the override
	if err := cfg.MergeFileOverride(overridePath); err != nil {
		t.Fatalf("MergeFileOverride failed: %v", err)
	}

	// Verify chatgpt was updated
	chatgpt, ok := cfg.Providers["chatgpt"]
	if !ok {
		t.Fatal("chatgpt provider should still exist after merge")
	}
	if len(chatgpt.Domains) != 2 {
		t.Errorf("chatgpt should have 2 domains after override, got %d: %v", len(chatgpt.Domains), chatgpt.Domains)
	}

	// Verify claude was NOT deleted (this is the bug fix)
	claude, ok := cfg.Providers["claude"]
	if !ok {
		t.Fatal("claude provider was silently deleted by MergeFileOverride (PR-002 regression)")
	}
	if !claude.Enabled {
		t.Error("claude should still be enabled")
	}
	if len(claude.Domains) != 1 || claude.Domains[0] != "claude.ai" {
		t.Errorf("claude domains should be unchanged, got %v", claude.Domains)
	}
}

// TestMergeFileOverride_AgentFieldMerged verifies that agent fields
// present in the override are applied without disturbing others.
func TestMergeFileOverride_AgentFieldMerged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Mode = "transparent"
	cfg.Agent.FailMode = PtrStr("fail_open")

	tmpDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "override.yaml")
	overrideYAML := []byte(`
agent:
  listen_port: 9999
  mode: "monitor"
`)
	if err := os.WriteFile(overridePath, overrideYAML, 0644); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	if err := cfg.MergeFileOverride(overridePath); err != nil {
		t.Fatalf("MergeFileOverride failed: %v", err)
	}

	if cfg.Agent.ListenPort != 9999 {
		t.Errorf("listen_port should be overridden to 9999, got %d", cfg.Agent.ListenPort)
	}
	if cfg.Agent.Mode != "monitor" {
		t.Errorf("mode should be overridden to monitor, got %s", cfg.Agent.Mode)
	}
	// These should be unchanged
	if cfg.Agent.FailMode == nil || *cfg.Agent.FailMode != "fail_open" {
		t.Errorf("fail_mode should remain fail_open, got %v", cfg.Agent.FailMode)
	}
}

// TestMergeFileOverride_NewProviderAdded verifies that a new provider
// in the override is added to the map without removing existing ones.
func TestMergeFileOverride_NewProviderAdded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Providers = ProvidersConfig{
		"chatgpt": {Enabled: true, Domains: []string{"chatgpt.com"}},
	}

	tmpDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "override.yaml")
	overrideYAML := []byte(`
providers:
  gemini:
    enabled: true
    domains:
      - "gemini.google.com"
`)
	if err := os.WriteFile(overridePath, overrideYAML, 0644); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	if err := cfg.MergeFileOverride(overridePath); err != nil {
		t.Fatalf("MergeFileOverride failed: %v", err)
	}

	// Original provider still present
	if _, ok := cfg.Providers["chatgpt"]; !ok {
		t.Fatal("chatgpt provider was deleted by merge")
	}
	// New provider was added
	if _, ok := cfg.Providers["gemini"]; !ok {
		t.Fatal("gemini provider was not added by merge")
	}
}

// TestMergeFileOverride_MissingFile verifies error handling for nonexistent override.
func TestMergeFileOverride_MissingFile(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.MergeFileOverride("/nonexistent/path/override.yaml")
	if err == nil {
		t.Error("expected error for missing override file")
	}
}

// TestVaultTTLValidation verifies TTL validation per AC-8 and T-815.
func TestVaultTTLValidation(t *testing.T) {
	tests := []struct {
		name    string
		ttl     string
		wantErr bool
	}{
		// Valid
		{"valid 0 infinite", "0", false},
		{"valid 24h", "24h", false},
		{"valid 168h default", "168h", false},
		{"valid 720h", "720h", false},
		{"valid empty uses default", "", false},
		// Invalid (not in AC-8 whitelist)
		{"invalid negative", "-5h", true},
		{"invalid unparseable", "15x", true},
		{"invalid sub-hour", "30m", true},
		{"invalid non-integer hours", "1h30m", true},
		{"invalid minutes only", "90m", true},
		{"invalid garbage", "forever", true},
		{"invalid 500h not whitelisted", "500h", true},
		{"invalid 1h not whitelisted", "1h", true},
		{"invalid 25h not whitelisted", "25h", true},
		{"invalid 9999h not whitelisted", "9999h", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Agent.Vault.TTL = tt.ttl
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestMergeFileOverride_InvalidYAML verifies error handling for bad YAML in override.
func TestMergeFileOverride_InvalidYAML(t *testing.T) {
	cfg := DefaultConfig()
	tmpDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "override.yaml")
	if err := os.WriteFile(overridePath, []byte(`this is not: [valid: yaml`), 0644); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	err := cfg.MergeFileOverride(overridePath)
	if err == nil {
		t.Error("expected error for invalid override YAML")
	}
}

// =============================================================================
// QINDU-0009 Config Tests (R-024, SR-CISO-11, *bool/*string safety)
// =============================================================================

// TestConfig_EnforceModeRejectsFailOpen verifies that enforce mode + fail_open
// is rejected by config validation (SR-CISO-11).
func TestConfig_EnforceModeRejectsFailOpen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Mode = "enforce"
	cfg.Agent.FailMode = PtrStr("fail_open")

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for enforce mode with fail_open")
	}
	if !strings.Contains(err.Error(), "incompatible") {
		t.Errorf("error should mention incompatibility, got: %v", err)
	}
}

// TestConfig_EnforceModeNilFailModeDefaultsFailClosed verifies that
// enforce mode with nil fail_mode defaults to fail_closed (valid).
func TestConfig_EnforceModeNilFailModeDefaultsFailClosed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Mode = "enforce"
	cfg.Agent.FailMode = nil

	err := cfg.Validate()
	if err != nil {
		t.Errorf("nil fail_mode in enforce mode should default to fail_closed and pass validation: %v", err)
	}

	// Verify FailModeValue() returns fail_closed.
	if mode := cfg.Agent.FailModeValue(); mode != "fail_closed" {
		t.Errorf("FailModeValue() = %q, want 'fail_closed'", mode)
	}
}

// TestConfig_EnforceModeExplicitFailClosedPasses verifies explicit
// fail_closed + enforce mode passes validation.
func TestConfig_EnforceModeExplicitFailClosedPasses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Mode = "enforce"
	cfg.Agent.FailMode = PtrStr("fail_closed")

	err := cfg.Validate()
	if err != nil {
		t.Errorf("explicit fail_closed in enforce mode should pass: %v", err)
	}
}

// TestConfig_PIILoggingNilDefaultsFalse verifies that nil PIILogging
// defaults to false (nil-safe).
func TestConfig_PIILoggingNilDefaultsFalse(t *testing.T) {
	var lc LoggingConfig
	// PIILogging is nil.
	if lc.PIILoggingValue() != false {
		t.Error("nil PIILogging must default to false")
	}
}

// TestConfig_PIILoggingExplicitFalse verifies explicit false is preserved.
func TestConfig_PIILoggingExplicitFalse(t *testing.T) {
	lc := LoggingConfig{PIILogging: PtrBool(false)}
	if lc.PIILoggingValue() != false {
		t.Error("explicit false PIILogging must return false")
	}
}

// TestConfig_PIILoggingExplicitTrue verifies explicit true is preserved.
func TestConfig_PIILoggingExplicitTrue(t *testing.T) {
	lc := LoggingConfig{PIILogging: PtrBool(true)}
	if lc.PIILoggingValue() != true {
		t.Error("explicit true PIILogging must return true")
	}
}

// TestConfig_CertCacheEnabledNilDefaultsTrue verifies nil CertCacheEnabled
// defaults to true.
func TestConfig_CertCacheEnabledNilDefaultsTrue(t *testing.T) {
	var tc TLSConfig
	if tc.CertCacheEnabledValue() != true {
		t.Error("nil CertCacheEnabled must default to true")
	}
}

// TestConfig_CertCacheEnabledExplicitFalse verifies explicit false is preserved.
func TestConfig_CertCacheEnabledExplicitFalse(t *testing.T) {
	tc := TLSConfig{CertCacheEnabled: PtrBool(false)}
	if tc.CertCacheEnabledValue() != false {
		t.Error("explicit false CertCacheEnabled must return false")
	}
}

// TestConfig_FailModeValue_MonitorNilDefaultsFailOpen verifies nil FailMode
// in monitor mode defaults to fail_open.
func TestConfig_FailModeValue_MonitorNilDefaultsFailOpen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Mode = "monitor"
	cfg.Agent.FailMode = nil
	if mode := cfg.Agent.FailModeValue(); mode != "fail_open" {
		t.Errorf("nil fail_mode in monitor mode must default to fail_open, got %q", mode)
	}
}

// TestConfig_FailModeValue_TransparentNilDefaultsFailOpen verifies nil FailMode
// in transparent mode defaults to fail_open.
func TestConfig_FailModeValue_TransparentNilDefaultsFailOpen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Mode = "transparent"
	cfg.Agent.FailMode = nil
	if mode := cfg.Agent.FailModeValue(); mode != "fail_open" {
		t.Errorf("nil fail_mode in transparent mode must default to fail_open, got %q", mode)
	}
}

// TestConfig_MergeFileOverride_StarBoolDistinguishesFalse verifies that
// MergeFileOverride correctly applies false values for *bool fields (R-024 fix).
func TestConfig_MergeFileOverride_StarBoolDistinguishesFalse(t *testing.T) {
	cfg := DefaultConfig()
	tmpDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "override.yaml")

	// Override with pii_logging: false and cert_cache_enabled: false.
	overrideYAML := `
logging:
  pii_logging: false
tls:
  cert_cache_enabled: false
`
	if err := os.WriteFile(overridePath, []byte(overrideYAML), 0644); err != nil {
		t.Fatalf("failed to write override: %v", err)
	}

	if err := cfg.MergeFileOverride(overridePath); err != nil {
		t.Fatalf("MergeFileOverride failed: %v", err)
	}

	if cfg.Logging.PIILogging == nil {
		t.Error("PIILogging should not be nil after override with explicit false")
	}
	if *cfg.Logging.PIILogging != false {
		t.Error("PIILogging should be false after override")
	}
	if cfg.TLS.CertCacheEnabled == nil {
		t.Error("CertCacheEnabled should not be nil after override with explicit false")
	}
	if *cfg.TLS.CertCacheEnabled != false {
		t.Error("CertCacheEnabled should be false after override")
	}
}

// TestConfig_MergeFileOverride_StarStringDistinguishesEmpty verifies that
// MergeFileOverride correctly applies *string overrides (R-024 fix).
func TestConfig_MergeFileOverride_StarStringDistinguishesEmpty(t *testing.T) {
	cfg := DefaultConfig()
	tmpDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "override.yaml")

	overrideYAML := `
agent:
  fail_mode: "fail_closed"
`
	if err := os.WriteFile(overridePath, []byte(overrideYAML), 0644); err != nil {
		t.Fatalf("failed to write override: %v", err)
	}

	if err := cfg.MergeFileOverride(overridePath); err != nil {
		t.Fatalf("MergeFileOverride failed: %v", err)
	}

	if cfg.Agent.FailMode == nil {
		t.Error("FailMode should not be nil after override")
	}
	if *cfg.Agent.FailMode != "fail_closed" {
		t.Errorf("FailMode should be 'fail_closed', got %q", *cfg.Agent.FailMode)
	}
}
