package proxy

import (
	"bytes"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Tarekinh0/qindu/internal/policy"
	qinduTls "github.com/Tarekinh0/qindu/internal/tls"
)

// stubStore is a minimal CAStore for test that does nothing.
type stubStore struct{}

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
