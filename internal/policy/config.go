// Package policy provides configuration loading, domain routing, and PAC generation.
package policy

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the full Qindu configuration.
type Config struct {
	Providers ProvidersConfig `yaml:"providers"`
	Agent     AgentConfig     `yaml:"agent"`
	Logging   LoggingConfig   `yaml:"logging"`
	TLS       TLSConfig       `yaml:"tls"`
}

// MonitorConfig holds monitor-mode settings including path-based scan filtering.
type MonitorConfig struct {
	ScanPaths []string `yaml:"scan_paths"`
}

// VaultConfig holds vault (persistent encrypted storage) settings.
type VaultConfig struct {
	TTL string `yaml:"ttl"` // "24h", "168h" (default), "720h", "0" = infinite (WARNING logged)
}

// AgentConfig holds agent-level settings.
type AgentConfig struct {
	ListenAddr string        `yaml:"listen_addr"`
	Mode       string        `yaml:"mode"`
	FailMode   string        `yaml:"fail_mode"`
	ListenPort int           `yaml:"listen_port"`
	Monitor    MonitorConfig `yaml:"monitor"`
	Vault      VaultConfig   `yaml:"vault"`
}

// TLSConfig holds TLS/CA settings.
type TLSConfig struct {
	CAName             string `yaml:"ca_name"`
	CAKeyAlgorithm     string `yaml:"ca_key_algorithm"`
	UpstreamValidation string `yaml:"upstream_validation"`
	CAValidityYears    int    `yaml:"ca_validity_years"`
	CertCacheEnabled   bool   `yaml:"cert_cache_enabled"`
}

// ProvidersConfig maps provider names to their settings.
type ProvidersConfig map[string]ProviderConfig

// ProviderConfig holds configuration for a single AI provider.
type ProviderConfig struct {
	Domains []string `yaml:"domains"`
	Enabled bool     `yaml:"enabled"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	PIILogging bool   `yaml:"pii_logging"`
	Output     string `yaml:"output"`  // "stderr" (default), "file", or "both"
	LogDir     string `yaml:"log_dir"` // directory for log files (empty = auto-detect)
}

// LoadConfig reads and parses a YAML config file, returning the validated Config.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// ParseConfig parses YAML bytes into a validated Config.
// Note: LoadConfig is preferred for production use (reads from file).
// ParseConfig is exported for test and programmatic use; it validates
// after parsing to prevent invalid configs from being created.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

// defaultMonitorScanPaths returns the built-in scan path whitelist for monitor mode.
// These cover major AI chat API endpoints.
func defaultMonitorScanPaths() []string {
	return []string{
		"/conversation",     // ChatGPT (backend-anon, backend-api)
		"/v1/messages",      // Claude / Anthropic
		"/chat/completions", // DeepSeek, OpenAI-compatible APIs
		"generateContent",   // Gemini (matches :generateContent or /generateContent)
		"/chat/",            // Copilot, various chat endpoints
	}
}

// Validate checks the config for security and correctness requirements.
func (c *Config) Validate() error {
	if c.Agent.ListenAddr == "" {
		return fmt.Errorf("agent.listen_addr is required")
	}

	// SR4: must bind to loopback only
	ip := net.ParseIP(c.Agent.ListenAddr)
	if ip == nil {
		return fmt.Errorf("agent.listen_addr is not a valid IP: %s", c.Agent.ListenAddr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("agent.listen_addr must be a loopback address (127.0.0.1 or ::1), got: %s", c.Agent.ListenAddr)
	}

	if c.Agent.ListenPort <= 0 || c.Agent.ListenPort > 65535 {
		return fmt.Errorf("agent.listen_port must be between 1 and 65535, got: %d", c.Agent.ListenPort)
	}

	// SR-11: Validate agent.mode — must be one of transparent, monitor, enforce.
	switch c.Agent.Mode {
	case "transparent", "monitor", "enforce":
		// Valid modes.
	default:
		return fmt.Errorf("agent.mode must be one of 'transparent', 'monitor', or 'enforce', got: %s", c.Agent.Mode)
	}

	// Validate monitor scan paths — use defaults if none configured.
	if len(c.Agent.Monitor.ScanPaths) == 0 {
		c.Agent.Monitor.ScanPaths = defaultMonitorScanPaths()
	}
	for i, p := range c.Agent.Monitor.ScanPaths {
		if p == "" {
			return fmt.Errorf("agent.monitor.scan_paths[%d] must be non-empty", i)
		}
	}

	// Validate logging.output — must be one of stderr, file, both, or empty.
	switch c.Logging.Output {
	case "stderr", "file", "both", "":
		// Valid output destinations.
	default:
		return fmt.Errorf("logging.output must be one of 'stderr', 'file', or 'both', got: %s", c.Logging.Output)
	}

	// SR3: upstream validation must be "system" or "insecure"
	if c.TLS.UpstreamValidation != "system" && c.TLS.UpstreamValidation != "insecure" {
		return fmt.Errorf("tls.upstream_validation must be 'system' or 'insecure', got: %s", c.TLS.UpstreamValidation)
	}

	if c.TLS.CAValidityYears <= 0 {
		return fmt.Errorf("tls.ca_validity_years must be positive, got: %d", c.TLS.CAValidityYears)
	}

	if c.TLS.CAKeyAlgorithm != "ECDSA_P256" {
		return fmt.Errorf("tls.ca_key_algorithm must be 'ECDSA_P256', got: %s", c.TLS.CAKeyAlgorithm)
	}

	// Validate vault TTL if configured.
	if err := c.Agent.Vault.Validate(); err != nil {
		return fmt.Errorf("invalid agent.vault config: %w", err)
	}

	return nil
}

// Validate checks the vault TTL config and returns an error for invalid values.
// Valid: "0" (infinite), "24h", "168h", "720h".
// Rejects: negative, sub-hour, unparseable, or non-hour durations.
func (v *VaultConfig) Validate() error {
	// Empty or unset TTL defaults to 168h (handled elsewhere), not an error.
	if v.TTL == "" {
		return nil
	}

	// "0" means infinite — accepted with warning at agent startup.
	if v.TTL == "0" {
		return nil
	}

	d, err := time.ParseDuration(v.TTL)
	if err != nil {
		return fmt.Errorf("ttl must be a valid Go duration (e.g., '24h', '168h'), got: %q", v.TTL)
	}

	// Reject negative durations.
	if d < 0 {
		return fmt.Errorf("ttl must not be negative, got: %q", v.TTL)
	}

	// Reject sub-hour durations.
	if d < time.Hour {
		return fmt.Errorf("ttl must be at least 1h, got: %q", v.TTL)
	}

	// Reject non-hour-based durations (e.g., "30m", "1h30m").
	// Only pure hour durations like "24h", "168h" are accepted.
	hours := d.Hours()
	if hours != float64(int(hours)) {
		return fmt.Errorf("ttl must be a whole number of hours (e.g., '24h', '168h'), got: %q", v.TTL)
	}

	return nil
}

// AllAIDomains returns a flat, deduplicated list of all enabled AI provider domains.
func (c *Config) AllAIDomains() []string {
	seen := make(map[string]bool)
	var domains []string
	for _, provider := range c.Providers {
		if !provider.Enabled {
			continue
		}
		for _, d := range provider.Domains {
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	return domains
}

// ListenAddress returns the full listen address string.
func (c *Config) ListenAddress() string {
	return fmt.Sprintf("%s:%d", c.Agent.ListenAddr, c.Agent.ListenPort)
}

// UpstreamInsecure returns true if upstream TLS validation is disabled.
func (c *Config) UpstreamInsecure() bool {
	return c.TLS.UpstreamValidation == "insecure"
}

// MergeFileOverride applies a shallow override from a YAML file on top of the
// current config. Only fields present in the override file are modified; all
// other fields retain their current values. The merged result is validated.
//
// IMPORTANT: Unmarshaling directly into the receiver would replace entire maps
// (e.g., providers) instead of merging individual entries. We unmarshal into a
// temporary Config, then merge each section field-by-field.
func (c *Config) MergeFileOverride(overridePath string) error {
	data, err := os.ReadFile(overridePath)
	if err != nil {
		return fmt.Errorf("reading override file: %w", err)
	}

	var override Config
	if err := yaml.Unmarshal(data, &override); err != nil {
		return fmt.Errorf("parsing override config: %w", err)
	}

	// Merge agent settings (only override non-zero values)
	if override.Agent.ListenAddr != "" {
		c.Agent.ListenAddr = override.Agent.ListenAddr
	}
	if override.Agent.ListenPort != 0 {
		c.Agent.ListenPort = override.Agent.ListenPort
	}
	if override.Agent.Mode != "" {
		c.Agent.Mode = override.Agent.Mode
	}
	if override.Agent.FailMode != "" {
		c.Agent.FailMode = override.Agent.FailMode
	}
	if len(override.Agent.Monitor.ScanPaths) > 0 {
		c.Agent.Monitor.ScanPaths = override.Agent.Monitor.ScanPaths
	}
	// Merge vault settings.
	if override.Agent.Vault.TTL != "" {
		c.Agent.Vault.TTL = override.Agent.Vault.TTL
	}

	// Merge TLS settings
	if override.TLS.CAName != "" {
		c.TLS.CAName = override.TLS.CAName
	}
	if override.TLS.CAValidityYears != 0 {
		c.TLS.CAValidityYears = override.TLS.CAValidityYears
	}
	if override.TLS.CAKeyAlgorithm != "" {
		c.TLS.CAKeyAlgorithm = override.TLS.CAKeyAlgorithm
	}
	// CertCacheEnabled: yaml.v3 defaults bool to false, so we cannot distinguish
	// "not present" from "explicitly false". The override struct keeps the
	// zero-value, so we skip it to avoid forcing false on every merge.
	// If explicit bool override is needed, use a *bool pointer field.
	if override.TLS.UpstreamValidation != "" {
		c.TLS.UpstreamValidation = override.TLS.UpstreamValidation
	}

	// Merge providers — add/update individual entries, do not replace the entire map
	for name, prov := range override.Providers {
		if c.Providers == nil {
			c.Providers = make(ProvidersConfig)
		}
		c.Providers[name] = prov
	}

	// Merge logging settings
	if override.Logging.Level != "" {
		c.Logging.Level = override.Logging.Level
	}
	if override.Logging.Format != "" {
		c.Logging.Format = override.Logging.Format
	}
	if override.Logging.Output != "" {
		c.Logging.Output = override.Logging.Output
	}
	if override.Logging.LogDir != "" {
		c.Logging.LogDir = override.Logging.LogDir
	}
	// PIILogging: same bool zero-value problem as CertCacheEnabled — skipped.
	// If the override YAML does not contain "pii_logging", the field stays false
	// (zero value) and we do not overwrite the receiver's value.

	// Re-validate after merge
	if err := c.Validate(); err != nil {
		return fmt.Errorf("invalid config after override merge: %w", err)
	}
	return nil
}

// DefaultConfig returns a Config with safe defaults.
// The default mode is "monitor" (PII detection without modification).
// This matches the shipped YAML default to avoid dual sources of truth.
func DefaultConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			ListenAddr: "127.0.0.1",
			ListenPort: 8787,
			Mode:       "monitor",
			FailMode:   "fail_open",
			Monitor: MonitorConfig{
				ScanPaths: defaultMonitorScanPaths(),
			},
			Vault: VaultConfig{
				TTL: "168h",
			},
		},
		TLS: TLSConfig{
			CAName:             "Qindu AI Privacy CA",
			CAValidityYears:    10,
			CAKeyAlgorithm:     "ECDSA_P256",
			CertCacheEnabled:   true,
			UpstreamValidation: "system",
		},
		Providers: ProvidersConfig{
			"chatgpt": {Enabled: true, Domains: []string{"chatgpt.com"}},
			"claude":  {Enabled: true, Domains: []string{"claude.ai"}},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			PIILogging: false,
			Output:     "stderr",
			LogDir:     "",
		},
	}
}
