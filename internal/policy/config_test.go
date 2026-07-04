package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseConfig_ValidYAML verifies that a valid YAML config is parsed correctly.
func TestParseConfig_ValidYAML(t *testing.T) {
	yamlData := []byte(`
agent:
  listen_addr: "127.0.0.1"
  listen_port: 8787
  mode: "enforce"
  fail_mode: "fail_open"

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
	cfg.Agent.FailMode = "fail_open"

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
	if cfg.Agent.FailMode != "fail_open" {
		t.Errorf("fail_mode should remain fail_open, got %s", cfg.Agent.FailMode)
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
