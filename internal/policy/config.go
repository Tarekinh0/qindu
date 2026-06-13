// Package policy provides configuration loading, domain routing, and PAC generation.
package policy

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the full Qindu configuration.
type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	TLS       TLSConfig       `yaml:"tls"`
	Providers ProvidersConfig `yaml:"providers"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// AgentConfig holds agent-level settings.
type AgentConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`
	Mode       string `yaml:"mode"`
	FailMode   string `yaml:"fail_mode"`
}

// TLSConfig holds TLS/CA settings.
type TLSConfig struct {
	CAName             string `yaml:"ca_name"`
	CAValidityYears    int    `yaml:"ca_validity_years"`
	CAKeyAlgorithm     string `yaml:"ca_key_algorithm"`
	CertCacheEnabled   bool   `yaml:"cert_cache_enabled"`
	UpstreamValidation string `yaml:"upstream_validation"`
}

// ProvidersConfig maps provider names to their settings.
type ProvidersConfig map[string]ProviderConfig

// ProviderConfig holds configuration for a single AI provider.
type ProviderConfig struct {
	Enabled bool     `yaml:"enabled"`
	Domains []string `yaml:"domains"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	PIILogging bool   `yaml:"pii_logging"`
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

// ParseConfig parses YAML bytes into a Config (used for tests).
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
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

	return nil
}

// AllAIDomains returns a flat list of all enabled AI provider domains.
func (c *Config) AllAIDomains() []string {
	var domains []string
	for _, provider := range c.Providers {
		if !provider.Enabled {
			continue
		}
		domains = append(domains, provider.Domains...)
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

// DefaultConfig returns a Config with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			ListenAddr: "127.0.0.1",
			ListenPort: 8787,
			Mode:       "enforce",
			FailMode:   "fail_open",
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
		},
	}
}
