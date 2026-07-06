// Package policy provides configuration loading, domain routing, and PAC generation.
package policy

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DebugConfig holds debug-mode settings (flow inspector, etc.).
// All features default to disabled for production safety.
type DebugConfig struct {
	FlowInspector *bool `yaml:"flow_inspector"` // *bool to distinguish "not set" from false
}

// FlowInspectorValue returns the flow_inspector setting with nil-safe default (false).
func (d *DebugConfig) FlowInspectorValue() bool {
	if d.FlowInspector == nil {
		return false
	}
	return *d.FlowInspector
}

// Config represents the full Qindu configuration.
type Config struct {
	Providers ProvidersConfig `yaml:"providers"`
	Agent     AgentConfig     `yaml:"agent"`
	Logging   LoggingConfig   `yaml:"logging"`
	TLS       TLSConfig       `yaml:"tls"`
	Debug     DebugConfig     `yaml:"debug"`
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
	FailMode   *string       `yaml:"fail_mode"` // *string to distinguish "not set" from "explicitly empty" (R-024)
	Vault      VaultConfig   `yaml:"vault"`
	Monitor    MonitorConfig `yaml:"monitor"`
	ListenPort int           `yaml:"listen_port"`
}

// FailModeValue returns the fail_mode string with nil-safe default.
// For enforce mode: defaults to "fail_closed".
// For monitor/transparent mode: defaults to "fail_open".
func (a *AgentConfig) FailModeValue() string {
	if a.FailMode == nil {
		if a.Mode == "enforce" {
			return "fail_closed"
		}
		return "fail_open"
	}
	return *a.FailMode
}

// TLSConfig holds TLS/CA settings.
type TLSConfig struct {
	CAName             string `yaml:"ca_name"`
	CAKeyAlgorithm     string `yaml:"ca_key_algorithm"`
	UpstreamValidation string `yaml:"upstream_validation"`
	CAValidityYears    int    `yaml:"ca_validity_years"`
	CertCacheEnabled   *bool  `yaml:"cert_cache_enabled"` // *bool to distinguish "not set" from false (R-024)
}

// CertCacheEnabledValue returns the cert_cache setting with nil-safe default (true).
func (t *TLSConfig) CertCacheEnabledValue() bool {
	if t.CertCacheEnabled == nil {
		return true
	}
	return *t.CertCacheEnabled
}

// ProvidersConfig maps provider names to their settings.
type ProvidersConfig map[string]ProviderConfig

// Validate checks provider configurations for correctness and security (PR-102).
// 1. Rejects empty provider names.
// 2. Rejects empty domain lists for enabled providers.
// 3. Validates each domain: no slashes, wildcards, spaces, or colons (ports go in a separate field).
// 4. Detects duplicate domains across providers and returns an error.
func (pc ProvidersConfig) Validate() error {
	seenDomains := make(map[string]string) // domain → first provider name

	for name, prov := range pc {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("provider name must not be empty")
		}

		if !prov.Enabled {
			continue
		}

		if len(prov.Domains) == 0 {
			return fmt.Errorf("provider %q is enabled but has no domains configured", name)
		}

		for _, domain := range prov.Domains {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				return fmt.Errorf("provider %q has an empty domain entry", name)
			}

			// Reject slashes.
			if strings.ContainsAny(domain, "/\\") {
				return fmt.Errorf("provider %q domain %q must not contain slashes", name, domain)
			}

			// Reject wildcards.
			if strings.Contains(domain, "*") {
				return fmt.Errorf("provider %q domain %q must not contain wildcards", name, domain)
			}

			// Reject spaces.
			if strings.Contains(domain, " ") {
				return fmt.Errorf("provider %q domain %q must not contain spaces", name, domain)
			}

			// Reject colons (ports belong in a separate field).
			if strings.Contains(domain, ":") {
				return fmt.Errorf("provider %q domain %q must not contain a port (use a separate port field)", name, domain)
			}

			// Detect duplicate domains across providers.
			normalized := strings.ToLower(domain)
			if firstProvider, exists := seenDomains[normalized]; exists {
				return fmt.Errorf("duplicate domain %q found in providers %q and %q", domain, firstProvider, name)
			}
			seenDomains[normalized] = name
		}
	}

	return nil
}

// ProviderConfig holds configuration for a single AI provider.
type ProviderConfig struct {
	Domains []string `yaml:"domains"`
	Enabled bool     `yaml:"enabled"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`      // "stderr" (default), "file", or "both"
	LogDir     string `yaml:"log_dir"`     // directory for log files (empty = auto-detect)
	PIILogging *bool  `yaml:"pii_logging"` // *bool to distinguish "not set" from false (R-024)
}

// PIILoggingValue returns the pii_logging setting with nil-safe default (false).
func (l *LoggingConfig) PIILoggingValue() bool {
	if l.PIILogging == nil {
		return false
	}
	return *l.PIILogging
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

	// SR-CISO-11: enforce mode + fail_open is incompatible.
	if c.Agent.Mode == "enforce" && c.Agent.FailMode != nil && *c.Agent.FailMode == "fail_open" {
		return fmt.Errorf("agent.fail_mode 'fail_open' is incompatible with enforce mode — enforce mode requires fail_closed to prevent PII leakage. Set fail_mode to 'fail_closed' or switch to monitor mode.")
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

	// Validate provider configs (PR-102).
	if err := c.Providers.Validate(); err != nil {
		return fmt.Errorf("invalid providers config: %w", err)
	}

	return nil
}

// Validate checks the vault TTL config and returns an error for invalid values.
// Valid: "0" (infinite), "24h", "168h", "720h".
// Rejects: negative, sub-hour, unparseable, or non-hour durations.
func (v *VaultConfig) Validate() error {
	_, err := v.ParseTTL()
	return err
}

// ParseTTL parses the vault TTL string into a time.Duration.
// Valid per AC-8: "0" (infinite), "24h", "168h" (default), "720h".
// Returns an error for any other value.
func (v *VaultConfig) ParseTTL() (time.Duration, error) {
	// Empty or unset TTL defaults to 168h.
	if v.TTL == "" {
		return 168 * time.Hour, nil
	}

	// "0" means infinite — accepted with warning at agent startup.
	if v.TTL == "0" {
		return 0, nil
	}

	// AC-8 whitelist: only these three TTL durations are valid.
	// This must be checked before ParseDuration to ensure any value
	// outside the whitelist is rejected with a clear error message,
	// regardless of whether it happens to parse as a valid duration.
	switch v.TTL {
	case "24h", "168h", "720h":
		// fall through to parse
	default:
		return 0, fmt.Errorf("ttl must be one of '0', '24h', '168h', '720h', got: %q", v.TTL)
	}

	d, err := time.ParseDuration(v.TTL)
	if err != nil {
		return 0, fmt.Errorf("ttl must be a valid Go duration (e.g., '24h', '168h'), got: %q", v.TTL)
	}

	// Defense-in-depth: the whitelist above already guarantees these are
	// positive whole-hour durations, but these checks remain in case the
	// whitelist is modified in the future.

	// Reject negative durations.
	if d < 0 {
		return 0, fmt.Errorf("ttl must not be negative, got: %q", v.TTL)
	}

	// Reject sub-hour durations.
	if d < time.Hour {
		return 0, fmt.Errorf("ttl must be at least 1h, got: %q", v.TTL)
	}

	// Reject non-hour-based durations (e.g., "30m", "1h30m").
	hours := d.Hours()
	if hours != float64(int(hours)) {
		return 0, fmt.Errorf("ttl must be a whole number of hours (e.g., '24h', '168h'), got: %q", v.TTL)
	}

	return d, nil
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
	if override.Agent.FailMode != nil {
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
	// CertCacheEnabled: *bool pointer distinguishes "not set" (nil) from "explicitly false" (*false).
	// R-024 migration: now correct.
	if override.TLS.CertCacheEnabled != nil {
		c.TLS.CertCacheEnabled = override.TLS.CertCacheEnabled
	}
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

	// Merge debug settings (DD-1: flow_inspector)
	if override.Debug.FlowInspector != nil {
		c.Debug.FlowInspector = override.Debug.FlowInspector
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
	// PIILogging: *bool pointer distinguishes "not set" from "explicitly false" (R-024).
	if override.Logging.PIILogging != nil {
		c.Logging.PIILogging = override.Logging.PIILogging
	}

	// Re-validate after merge
	if err := c.Validate(); err != nil {
		return fmt.Errorf("invalid config after override merge: %w", err)
	}
	return nil
}

// PtrBool returns a pointer to a bool.
func PtrBool(b bool) *bool { return &b }

// PtrStr returns a pointer to a string.
func PtrStr(s string) *string { return &s }

// DefaultConfig returns a Config with safe defaults.
// The default mode is "monitor" (PII detection without modification).
// This matches the shipped YAML default to avoid dual sources of truth.
func DefaultConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			ListenAddr: "127.0.0.1",
			ListenPort: 8787,
			Mode:       "monitor",
			FailMode:   PtrStr("fail_open"),
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
			CertCacheEnabled:   PtrBool(true),
			UpstreamValidation: "system",
		},
		Providers: ProvidersConfig{
			"chatgpt": {Enabled: true, Domains: []string{"chatgpt.com"}},
			"claude":  {Enabled: true, Domains: []string{"claude.ai"}},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			PIILogging: PtrBool(false),
			Output:     "stderr",
			LogDir:     "",
		},
		Debug: DebugConfig{
			FlowInspector: PtrBool(false),
		},
	}
}
