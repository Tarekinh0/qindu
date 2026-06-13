package policy

import (
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

// TestParseConfig_EmptyYAML verifies that empty YAML returns defaults.
func TestParseConfig_EmptyYAML(t *testing.T) {
	emptyYAML := []byte(``)

	cfg, err := ParseConfig(emptyYAML)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	// Empty config validation will fail on missing listen_addr
	err = cfg.Validate()
	if err == nil {
		t.Error("expected validation error for empty config, got nil")
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
