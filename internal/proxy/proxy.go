package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Tarekinh0/qindu/internal/interceptor"
	"github.com/Tarekinh0/qindu/internal/pii"
	"github.com/Tarekinh0/qindu/internal/policy"
	"github.com/Tarekinh0/qindu/internal/providers"
	_ "github.com/Tarekinh0/qindu/internal/providers/all" // side-effect registration
	"github.com/Tarekinh0/qindu/internal/service"
	qinduTls "github.com/Tarekinh0/qindu/internal/tls"
)

// DialFunc is a function that establishes a TLS connection to an upstream server.
type DialFunc func(network, addr string, config *tls.Config) (*tls.Conn, error)

// Proxy is the main Qindu HTTP/S proxy that handles CONNECT tunneling
// and local endpoints (PAC, health).
type Proxy struct {
	startTime    time.Time
	interceptor  Interceptor
	config       *policy.Config
	ca           *qinduTls.CA
	certCache    *qinduTls.CertCache
	domainRouter *policy.DomainRouter
	logger       *slog.Logger
	rootCAs      *x509.CertPool
	dialTLS      DialFunc
	version      string
}

// NewProxy creates a new Proxy instance.
// Returns an error if proxy initialization fails, including when
// an unimplemented agent.mode (e.g., "enforce") is requested.
func NewProxy(
	cfg *policy.Config,
	ca *qinduTls.CA,
	certCache *qinduTls.CertCache,
	logger *slog.Logger,
	version string,
) (*Proxy, error) {
	// Select the appropriate interceptor based on configured mode.
	// Engine creation is deferred to selectInterceptor to avoid
	// paying for what we don't use in transparent mode (PR-100).
	selectedInterceptor, err := selectInterceptor(cfg, logger)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		config:       cfg,
		ca:           ca,
		certCache:    certCache,
		domainRouter: policy.NewDomainRouter(cfg.AllAIDomains()),
		interceptor:  selectedInterceptor,
		logger:       logger,
		startTime:    time.Now(),
		version:      version,
	}, nil
}

// selectInterceptor chooses the appropriate Interceptor implementation
// based on the agent.mode config field (SR-12).
// Returns an error when the requested mode cannot be activated,
// including when "enforce" is requested before implementation (PR-001).
// The PII detection engine is only created for monitor mode to avoid
// paying for what we don't use in transparent mode (PR-100).
//
// For monitor mode in QINDU-0011, selectInterceptor builds a provider plugin
// registry and returns a providerDispatcher that routes per-domain:
// known providers get ProviderInterceptor (optimized text extraction),
// unknown providers fall back to MonitorInterceptor (raw scanning).
func selectInterceptor(cfg *policy.Config, logger *slog.Logger) (Interceptor, error) {
	mode := cfg.Agent.Mode

	switch mode {
	case "transparent":
		return &NoOpInterceptor{}, nil

	case "monitor":
		engine := pii.NewEngine(pii.DefaultMaxInputBytes,
			pii.NewEmailRecognizer(),
			pii.NewPhoneRecognizer(),
			pii.NewIBANRecognizer(),
			pii.NewCreditCardRecognizer(),
			pii.NewJWTRecognizer(),
			pii.NewSecretPrefixRecognizer(),
			pii.NewSecretEntropyRecognizer(),
			pii.NewPrivateKeyRecognizer(),
			pii.NewNameFromEmailRecognizer(),
		)

		logger.Info("Monitor mode active: PII detection enabled, traffic passed through unmodified. PII still reaches AI providers. Use enforce mode to tokenize PII.",
			"pii_logging", cfg.Logging.PIILogging,
		)

		mi, err := interceptor.NewMonitorInterceptor(engine, cfg.Logging.PIILogging, logger, cfg.Agent.Monitor.ScanPaths)
		if err != nil {
			return nil, fmt.Errorf("creating monitor interceptor: %w", err)
		}

		// Build provider plugin registry for domain-based routing.
		providerMap := buildProviderRegistry(cfg, engine, logger)

		if len(providerMap) == 0 {
			// No provider plugins registered — use MonitorInterceptor directly.
			logger.Info("No provider plugins registered, using MonitorInterceptor for all domains")
			return mi, nil
		}

		logger.Info("Provider plugins registered for domain-based routing",
			"domain_count", len(providerMap),
		)

		return &providerDispatcher{
			fallback:      mi,
			providers:     providerMap,
			sortedDomains: buildSortedDomains(providerMap),
			logger:        logger,
		}, nil

	case "enforce":
		// Check for provider plugins: enforce mode is unsupported for providers (DPO-R5.1).
		if hasEnabledProviders(cfg, logger) {
			providerNames := enabledProviderNames(cfg, logger)
			return nil, fmt.Errorf(
				"enforce mode is not yet supported for provider(s): %s (pending QINDU-0009). Set mode to 'monitor' or disable this provider.",
				strings.Join(providerNames, ", "),
			)
		}
		return nil, fmt.Errorf("agent.mode 'enforce' is not yet implemented in this version")

	default:
		logger.Error("Unknown agent.mode, falling back to transparent (NoOpInterceptor)",
			"mode", mode,
		)
		return &NoOpInterceptor{}, nil
	}
}

// domainEntry pairs a normalized domain with its interceptor for sorted lookup.
type domainEntry struct {
	domain string
	pi     Interceptor
}

// providerDispatcher implements Interceptor by routing between provider-specific
// interceptors based on the request Host. It falls back to a MonitorInterceptor
// for domains without a registered provider plugin.
type providerDispatcher struct {
	fallback      Interceptor
	providers     map[string]Interceptor // normalized domain → ProviderInterceptor
	sortedDomains []domainEntry          // length-descending, pre-computed at construction (PR-103)
	logger        *slog.Logger
}

// InterceptRequest dispatches to the interceptor matching the request Host.
func (d *providerDispatcher) InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error) {
	ic := d.selectForHost(req.Host)
	return ic.InterceptRequest(req)
}

// InterceptResponse dispatches to the interceptor matching the response's request Host.
func (d *providerDispatcher) InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error) {
	host := ""
	if resp.Request != nil {
		host = resp.Request.Host
	}
	ic := d.selectForHost(host)
	return ic.InterceptResponse(resp)
}

// selectForHost determines which interceptor to use for a given host.
// Normalizes the host per CS-11-07 and matches against the provider registry.
// Uses deterministic ordering: longest domain suffix matches first (PR-105).
// The sorted domain list is pre-computed at construction time (PR-103).
func (d *providerDispatcher) selectForHost(host string) Interceptor {
	host = sanitizeHostForDispatch(host)
	if host == "" {
		return d.fallback
	}

	// Exact match.
	if pi, ok := d.providers[host]; ok {
		return pi
	}

	// Suffix match with deterministic ordering: sorted domains are length-descending,
	// so more specific domains (chat.openai.com) match before less specific ones (openai.com).
	for _, entry := range d.sortedDomains {
		if strings.HasSuffix(host, "."+entry.domain) {
			return entry.pi
		}
	}

	// Fallback to MonitorInterceptor.
	return d.fallback
}

// buildSortedDomains takes a provider map and returns a length-descending sorted slice
// of domain entries for deterministic suffix matching (PR-103, PR-105).
func buildSortedDomains(providers map[string]Interceptor) []domainEntry {
	entries := make([]domainEntry, 0, len(providers))
	for domain, pi := range providers {
		entries = append(entries, domainEntry{domain, pi})
	}
	sort.Slice(entries, func(i, j int) bool {
		return len(entries[i].domain) > len(entries[j].domain)
	})
	return entries
}

// buildProviderRegistry creates ProviderInterceptors for each enabled provider
// that has a registered plugin. Maps normalized domains to interceptors.
func buildProviderRegistry(cfg *policy.Config, engine *pii.Engine, logger *slog.Logger) map[string]Interceptor {
	registry := make(map[string]Interceptor)

	for name, provCfg := range cfg.Providers {
		if !provCfg.Enabled {
			continue
		}

		plugin := providers.Create(name, logger)
		if plugin == nil {
			continue
		}

		pi, err := interceptor.NewProviderInterceptor(
			engine, plugin, cfg.Logging.PIILogging, logger,
		)
		if err != nil {
			logger.Warn("Failed to create ProviderInterceptor, skipping provider",
				"provider", name,
				"error", err,
			)
			continue
		}

		// Map each configured domain to this interceptor.
		for _, domain := range provCfg.Domains {
			normalized := strings.ToLower(strings.TrimSpace(domain))
			if normalized == "" {
				continue
			}
			// PR-101: detect duplicate domains across providers.
			if existing, exists := registry[normalized]; exists && existing != pi {
				logger.Warn("Domain conflict: domain claimed by multiple providers, last write wins",
					"domain", normalized,
					"previous_provider", "another_provider",
					"current_provider", name,
				)
			}
			registry[normalized] = pi
			// PR-106: downgrade per-domain registration to DEBUG.
			logger.Debug("Provider plugin registered",
				"provider", name,
				"domain", normalized,
			)
		}
	}

	return registry
}

// sanitizeHostForDispatch normalizes a hostname for domain routing (CS-11-07).
// Strips port, lowercases, rejects empty and NUL-containing hosts.
func sanitizeHostForDispatch(host string) string {
	if host == "" {
		return ""
	}

	// Reject hosts with NUL bytes or control characters.
	if strings.IndexByte(host, 0) >= 0 {
		return ""
	}
	for _, r := range host {
		if r < 32 || r > 126 {
			return ""
		}
	}

	host = strings.ToLower(host)

	// Strip port if present, being careful not to strip IPv6 address colons.
	if idx := strings.LastIndex(host, "]:"); idx > 0 {
		// IPv6 with port: [::1]:8080 → [::1]
		// idx is the position of ']' in "]:", so host[:idx+1] includes the bracket.
		host = host[:idx+1]
	} else if idx := strings.LastIndexByte(host, ':'); idx > 0 {
		// Only strip if the colon is NOT inside IPv6 brackets.
		// Bare IPv6 like [::1] has a leading '[' before the last ':', so skip it.
		if !strings.Contains(host[:idx], "[") {
			host = host[:idx]
		}
	}

	return host
}

// hasEnabledProviders returns true if any provider with a registered plugin is enabled.
func hasEnabledProviders(cfg *policy.Config, logger *slog.Logger) bool {
	for name, provCfg := range cfg.Providers {
		if !provCfg.Enabled {
			continue
		}
		if providers.Create(name, logger) != nil {
			return true
		}
	}
	return false
}

// enabledProviderNames returns the names of enabled providers with registered plugins.
func enabledProviderNames(cfg *policy.Config, logger *slog.Logger) []string {
	var names []string
	for name, provCfg := range cfg.Providers {
		if !provCfg.Enabled {
			continue
		}
		if providers.Create(name, logger) != nil {
			names = append(names, name)
		}
	}
	return names
}

// ServeHTTP implements the http.Handler interface.
// It dispatches CONNECT requests to the CONNECT handler and
// GET/HEAD requests to local endpoints (PAC, health).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodConnect:
		p.handleCONNECT(w, r)
	default:
		p.handleHTTP(w, r)
	}
}

// handleHTTP processes non-CONNECT HTTP requests (PAC, health).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/proxy.pac":
		p.handlePAC(w, r)
	case "/health":
		p.handleHealth(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handlePAC serves the dynamically-generated PAC file.
// Content-Type is set to application/x-ns-proxy-autoconfig.
func (p *Proxy) handlePAC(w http.ResponseWriter, r *http.Request) {
	domains := p.config.AllAIDomains()
	pacContent := policy.GeneratePAC(domains, p.config.ListenAddress())

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(pacContent)); err != nil {
		p.logger.Error("failed to write PAC response", "error", err)
	}
}

// handleHealth delegates to the service package's properly-typed health handler.
func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	service.HealthHandler(p.startTime, p.version)(w, r)
}
