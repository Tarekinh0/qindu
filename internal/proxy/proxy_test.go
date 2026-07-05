package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/policy"
	"github.com/Tarekinh0/qindu/internal/testutils"
	qinduTls "github.com/Tarekinh0/qindu/internal/tls"
)

// stubStore is a minimal CAStore for test that does nothing.
// Currently unused pending future proxy tests; the linter is suppressed
// to keep the scaffolding available for QINDU-0009 test wiring.
//
//nolint:unused
type stubStore struct{}

//nolint:unused
func (s *stubStore) StoreCA(ca *qinduTls.CA) error { return nil }

// testCA creates a minimal test CA for unit tests.
func testCA(t *testing.T) *qinduTls.CA {
	t.Helper()
	ca, _, err := qinduTls.GenerateCA("Qindu Test CA", 10, nil)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	return ca
}

func TestNewProxy_EnforceModeFatal(t *testing.T) {
	// PR-001: enforce mode must refuse to start, not silently fall back to monitor.
	ca := testCA(t)
	certCache := qinduTls.NewCertCache()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &policy.Config{
		Agent: policy.AgentConfig{
			ListenAddr: "127.0.0.1",
			ListenPort: 0,
			Mode:       "enforce",
		},
		TLS: policy.TLSConfig{
			CAName:             "Test CA",
			CAValidityYears:    10,
			CAKeyAlgorithm:     "ECDSA_P256",
			CertCacheEnabled:   true,
			UpstreamValidation: "system",
		},
		Providers: make(policy.ProvidersConfig),
		Logging: policy.LoggingConfig{
			Level:  "debug",
			Format: "text",
		},
	}

	_, err := NewProxy(cfg, ca, certCache, logger, "0.1.0-test")
	if err == nil {
		t.Fatal("expected error for enforce mode, got nil")
	}
	// Verify the error message mentions enforce mode.
	if !bytes.Contains([]byte(err.Error()), []byte("enforce")) {
		t.Errorf("error should mention 'enforce', got: %s", err.Error())
	}
}

func TestNewProxy_TransparentMode(t *testing.T) {
	ca := testCA(t)
	certCache := qinduTls.NewCertCache()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &policy.Config{
		Agent: policy.AgentConfig{
			ListenAddr: "127.0.0.1",
			ListenPort: 0,
			Mode:       "transparent",
		},
		TLS: policy.TLSConfig{
			CAName:             "Test CA",
			CAValidityYears:    10,
			CAKeyAlgorithm:     "ECDSA_P256",
			CertCacheEnabled:   true,
			UpstreamValidation: "system",
		},
		Providers: make(policy.ProvidersConfig),
		Logging: policy.LoggingConfig{
			Level:  "debug",
			Format: "text",
		},
	}

	p, err := NewProxy(cfg, ca, certCache, logger, "0.1.0-test")
	if err != nil {
		t.Fatalf("unexpected error for transparent mode: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
}

func TestNewProxy_MonitorMode(t *testing.T) {
	ca := testCA(t)
	certCache := qinduTls.NewCertCache()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &policy.Config{
		Agent: policy.AgentConfig{
			ListenAddr: "127.0.0.1",
			ListenPort: 0,
			Mode:       "monitor",
			Monitor: policy.MonitorConfig{
				ScanPaths: []string{"/v1/messages", "/chat/completions"},
			},
		},
		TLS: policy.TLSConfig{
			CAName:             "Test CA",
			CAValidityYears:    10,
			CAKeyAlgorithm:     "ECDSA_P256",
			CertCacheEnabled:   true,
			UpstreamValidation: "system",
		},
		Providers: make(policy.ProvidersConfig),
		Logging: policy.LoggingConfig{
			Level:  "debug",
			Format: "text",
		},
	}

	p, err := NewProxy(cfg, ca, certCache, logger, "0.1.0-test")
	if err != nil {
		t.Fatalf("unexpected error for monitor mode: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
}

// TestNewProxy_DefaultConfigIsValid verifies that the default config (which
// now uses mode "monitor") produces a valid, startable proxy instance.
func TestNewProxy_DefaultConfigIsValid(t *testing.T) {
	ca := testCA(t)
	certCache := qinduTls.NewCertCache()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := policy.DefaultConfig()
	// Set log format to make it simpler.
	cfg.Logging.Format = "text"

	p, err := NewProxy(cfg, ca, certCache, logger, "0.1.0-test")
	if err != nil {
		t.Fatalf("unexpected error for default config (monitor mode): %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy from default config")
	}
}

// TestNewProxy_StartTimeIsSet verifies the proxy's startTime is initialized.
func TestNewProxy_StartTimeIsSet(t *testing.T) {
	ca := testCA(t)
	certCache := qinduTls.NewCertCache()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := policy.DefaultConfig()
	cfg.Agent.Mode = "transparent"
	cfg.Logging.Format = "text"

	before := time.Now()
	p, err := NewProxy(cfg, ca, certCache, logger, "0.1.0-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.startTime.Before(before) {
		t.Error("proxy startTime should be >= time of NewProxy call")
	}
}

// =============================================================================
// Domain Routing Unit Tests (PR-002)
// =============================================================================

// TestSanitizeHostForDispatch verifies the hostname sanitization logic
// per CS-11-07: strips port, lowercases, rejects NUL/control chars.
func TestSanitizeHostForDispatch(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "plain hostname", host: "chatgpt.com", want: "chatgpt.com"},
		{name: "hostname with port", host: "chatgpt.com:443", want: "chatgpt.com"},
		{name: "hostname with custom port", host: "example.com:8080", want: "example.com"},
		{name: "uppercase", host: "CHATGPT.COM", want: "chatgpt.com"},
		{name: "mixed case", host: "ChatGPT.com", want: "chatgpt.com"},
		{name: "empty string", host: "", want: ""},
		{name: "NUL byte", host: "host\x00.com", want: ""},
		{name: "control char start", host: "\x01evil.com", want: ""},
		{name: "control char DEL", host: "\x7fbad.com", want: ""},
		{name: "IPv4 with port", host: "127.0.0.1:9090", want: "127.0.0.1"},
		{name: "IPv6 with port", host: "[::1]:8080", want: "[::1]"},
		{name: "IPv6 no port (bare loopback)", host: "[::1]", want: "[::1]"},
		{name: "IPv6 no port (full address)", host: "[2001:db8::1]", want: "[2001:db8::1]"},
		{name: "subdomain", host: "sub.chatgpt.com", want: "sub.chatgpt.com"},
		{name: "domain with path-like suffix", host: "claude.ai", want: "claude.ai"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeHostForDispatch(tt.host)
			if got != tt.want {
				t.Errorf("sanitizeHostForDispatch(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// TestProviderDispatcher_SelectForHost verifies domain-based interceptor routing:
// exact match, suffix/subdomain match, no match fallback, port stripping,
// case insensitivity, empty host, and deterministic longest-match-first ordering.
func TestProviderDispatcher_SelectForHost(t *testing.T) {
	// Use NoOpInterceptor instances as sentinels — each has a unique identity
	// so we can verify that selectForHost returns the correct one.
	chatgptPI := &NoOpInterceptor{}
	claudePI := &NoOpInterceptor{}
	openaiPI := &NoOpInterceptor{}
	fallbackPI := &NoOpInterceptor{}

	// Build a dispatcher with multiple providers, including overlapping domains
	// to verify longest-match-first deterministic ordering (PR-105).
	// sortedDomains is populated via buildSortedDomains to exercise the
	// suffix-matching code path in selectForHost (PR-002).
	providerMap := map[string]Interceptor{
		"chatgpt.com":    chatgptPI,
		"claude.ai":      claudePI,
		"openai.com":     openaiPI,
		"api.openai.com": openaiPI, // more specific subdomain — same PI
	}
	d := &providerDispatcher{
		fallback:      fallbackPI,
		providers:     providerMap,
		sortedDomains: buildSortedDomains(providerMap),
		logger:        slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	tests := []struct {
		name string
		host string
		want Interceptor
	}{
		{name: "exact match chatgpt", host: "chatgpt.com", want: chatgptPI},
		{name: "exact match claude", host: "claude.ai", want: claudePI},
		{name: "exact match openai", host: "openai.com", want: openaiPI},
		{name: "subdomain match", host: "sub.chatgpt.com", want: chatgptPI},
		{name: "deep subdomain", host: "a.b.chatgpt.com", want: chatgptPI},
		{name: "more specific subdomain wins (api.openai.com)", host: "api.openai.com", want: openaiPI},
		{name: "no match -> fallback", host: "unknown.com", want: fallbackPI},
		{name: "no match other provider", host: "gemini.google.com", want: fallbackPI},
		{name: "hostname with port", host: "chatgpt.com:443", want: chatgptPI},
		{name: "subdomain with port", host: "sub.claude.ai:8080", want: claudePI},
		{name: "case insensitive", host: "ChatGPT.com", want: chatgptPI},
		{name: "mixed case subdomain", host: "Sub.ChatGPT.Com", want: chatgptPI},
		{name: "empty host -> fallback", host: "", want: fallbackPI},
		{name: "NUL byte host -> fallback", host: "chatgpt\x00.com", want: fallbackPI},
		{name: "IPv6 no port -> exact match", host: "[::1]", want: fallbackPI},
		{name: "IPv6 loopback -> fallback", host: "[::1]:8080", want: fallbackPI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.selectForHost(tt.host)
			if got != tt.want {
				t.Errorf("selectForHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// TestProviderDispatcher_Match verifies InterceptRequest/InterceptResponse
// delegate to the correct interceptor based on Host.
func TestProviderDispatcher_Match(t *testing.T) {
	// Use sentinel interceptors that record calls to verify correct routing.
	recordPI := &recordingInterceptor{}
	fallbackPI := &recordingInterceptor{}

	d := &providerDispatcher{
		fallback: fallbackPI,
		providers: map[string]Interceptor{
			"chatgpt.com": recordPI,
		},
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	// Request to chatgpt.com — should hit recordPI.
	req := &http.Request{
		Method: "POST",
		Host:   "chatgpt.com",
		URL:    testutils.MustParseURL("/backend-anon/f/conversation"),
	}
	_, _, err := d.InterceptRequest(req)
	if err != nil {
		t.Fatalf("InterceptRequest failed: %v", err)
	}
	if !recordPI.lastInterceptRequestCalled {
		t.Error("expected recordPI.InterceptRequest to be called for chatgpt.com")
	}

	// Request to unknown.com — should hit fallbackPI.
	req2 := &http.Request{
		Method: "POST",
		Host:   "unknown.com",
		URL:    testutils.MustParseURL("/api/chat"),
	}
	_, _, err = d.InterceptRequest(req2)
	if err != nil {
		t.Fatalf("InterceptRequest for fallback failed: %v", err)
	}
	if !fallbackPI.lastInterceptRequestCalled {
		t.Error("expected fallbackPI.InterceptRequest to be called for unknown.com")
	}
}

// recordingInterceptor is a minimal Interceptor that records whether it was called.
type recordingInterceptor struct {
	lastInterceptRequestCalled  bool
	lastInterceptResponseCalled bool
}

func (r *recordingInterceptor) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	r.lastInterceptRequestCalled = true
	return req, io.NopCloser(strings.NewReader("")), nil
}

func (r *recordingInterceptor) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	r.lastInterceptResponseCalled = true
	return resp, resp.Body, nil
}

// TestBuildProviderRegistry verifies that buildProviderRegistry correctly
// creates ProviderInterceptors for enabled providers with domains, skips
// disabled providers, normalizes domain names, and handles unknown providers.
func TestBuildProviderRegistry(t *testing.T) {
	engine := pii.NewEngine(pii.DefaultMaxInputBytes,
		pii.NewEmailRecognizer(),
		pii.NewPhoneRecognizer(),
	)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("enabled provider with domains creates entries", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: true,
					Domains: []string{"chatgpt.com", "chat.openai.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}

		registry := buildProviderRegistry(cfg, engine, logger)
		if len(registry) != 2 {
			t.Fatalf("expected 2 domain entries, got %d", len(registry))
		}
		if _, ok := registry["chatgpt.com"]; !ok {
			t.Error("expected registry to contain chatgpt.com")
		}
		if _, ok := registry["chat.openai.com"]; !ok {
			t.Error("expected registry to contain chat.openai.com")
		}
	})

	t.Run("disabled provider is skipped", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: false,
					Domains: []string{"chatgpt.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}

		registry := buildProviderRegistry(cfg, engine, logger)
		if len(registry) != 0 {
			t.Fatalf("expected 0 entries for disabled provider, got %d", len(registry))
		}
	})

	t.Run("unknown provider name is skipped gracefully", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"nonexistent-provider": {
					Enabled: true,
					Domains: []string{"example.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}

		registry := buildProviderRegistry(cfg, engine, logger)
		if len(registry) != 0 {
			t.Fatalf("expected 0 entries for unknown provider, got %d", len(registry))
		}
	})

	t.Run("domain names are normalized (lowercase, trimmed)", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: true,
					Domains: []string{"  ChatGPT.COM  ", "chat.openai.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}

		registry := buildProviderRegistry(cfg, engine, logger)
		if _, ok := registry["chatgpt.com"]; !ok {
			t.Error("expected registry to contain normalized domain 'chatgpt.com'")
		}
		if _, ok := registry["ChatGPT.COM"]; ok {
			t.Error("registry should not contain un-normalized domain")
		}
	})

	t.Run("empty domain strings are skipped", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: true,
					Domains: []string{"  ", "", "chatgpt.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}

		registry := buildProviderRegistry(cfg, engine, logger)
		if len(registry) != 1 {
			t.Fatalf("expected 1 domain entry (empty domains skipped), got %d", len(registry))
		}
		if _, ok := registry["chatgpt.com"]; !ok {
			t.Error("expected chatgpt.com domain entry")
		}
	})

	t.Run("multiple enabled providers", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: true,
					Domains: []string{"chatgpt.com"},
				},
				"nonexistent": {
					Enabled: true,
					Domains: []string{"example.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}

		// Only chatgpt has a registered plugin; nonexistent should be skipped.
		registry := buildProviderRegistry(cfg, engine, logger)
		if len(registry) != 1 {
			t.Fatalf("expected 1 entry (chatgpt only), got %d", len(registry))
		}
	})
}

// TestHasEnabledProviders verifies the enforce-mode guard detection.
func TestHasEnabledProviders(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("enabled chatgpt provider detected", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: true,
					Domains: []string{"chatgpt.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}
		if !hasEnabledProviders(cfg, logger) {
			t.Error("expected hasEnabledProviders to return true for enabled chatgpt")
		}
	})

	t.Run("disabled provider not detected", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: false,
					Domains: []string{"chatgpt.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}
		if hasEnabledProviders(cfg, logger) {
			t.Error("expected hasEnabledProviders to return false for disabled chatgpt")
		}
	})

	t.Run("empty providers config", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{},
			Logging:   policy.LoggingConfig{PIILogging: false},
		}
		if hasEnabledProviders(cfg, logger) {
			t.Error("expected hasEnabledProviders to return false for empty providers")
		}
	})
}

// TestEnabledProviderNames verifies provider name collection for error messages.
func TestEnabledProviderNames(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("returns chatgpt name", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: true,
					Domains: []string{"chatgpt.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}
		names := enabledProviderNames(cfg, logger)
		if len(names) != 1 || names[0] != "chatgpt" {
			t.Errorf("expected [chatgpt], got %v", names)
		}
	})

	t.Run("disabled providers not listed", func(t *testing.T) {
		cfg := &policy.Config{
			Providers: policy.ProvidersConfig{
				"chatgpt": {
					Enabled: false,
					Domains: []string{"chatgpt.com"},
				},
			},
			Logging: policy.LoggingConfig{PIILogging: false},
		}
		names := enabledProviderNames(cfg, logger)
		if len(names) != 0 {
			t.Errorf("expected empty list, got %v", names)
		}
	})
}

// mustParseURL moved to internal/testutils/testutils.go (CS-002).
