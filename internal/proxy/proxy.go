package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"github.com/Tarekinh0/qindu/internal/vault"
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
	vaultManager *vault.VaultManager   // per-user vault manager for enforce mode (nil in transparent/monitor)
	engine       *pii.Engine           // shared PII engine for monitor/enforce mode (nil in transparent)
	flowRing     *interceptor.FlowRing // debug flow inspector ring buffer (nil when disabled)
	logger       *slog.Logger
	rootCAs      *x509.CertPool
	dialTLS      DialFunc
	version      string

	// providerByDomain maps normalized host → provider name for fast
	// resolveProviderForHost lookups (PR-003 cache).
	providerByDomain map[string]string
	// providerSortedDomains lists domain→name pairs sorted by domain length
	// descending for suffix-match resolution. Pre-computed at construction.
	providerSortedDomains []providerDomain
}

// NewProxy creates a new Proxy instance.
// Returns an error if proxy initialization fails, including when
// an unimplemented agent.mode (e.g., "enforce") is requested.
//
// VaultManager is optional (nil for transparent/monitor modes).
// It is required for enforce mode to manage per-user encrypted PII storage.
func NewProxy(
	cfg *policy.Config,
	ca *qinduTls.CA,
	certCache *qinduTls.CertCache,
	vaultManager *vault.VaultManager,
	logger *slog.Logger,
	version string,
) (*Proxy, error) {
	// Create shared PII engine for monitor/enforce modes (not transparent).
	var sharedEngine *pii.Engine
	if cfg.Agent.Mode != "transparent" {
		sharedEngine = pii.NewEngine(pii.DefaultMaxInputBytes,
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
	}

	// Select the appropriate interceptor based on configured mode.
	// Engine creation is deferred to selectInterceptor to avoid
	// paying for what we don't use in transparent mode (PR-100).
	selectedInterceptor, err := selectInterceptor(cfg, logger, sharedEngine)
	if err != nil {
		return nil, err
	}

	// Debug flow inspector: when enabled, wrap the interceptor with a
	// DebugInterceptor and create a FlowRing for ingress/egress capture.
	// Flag defaults to false (zero overhead, no ring buffer, no endpoint).
	var flowRing *interceptor.FlowRing
	if cfg.Debug.FlowInspectorValue() {
		flowRing = interceptor.NewFlowRing()
		selectedInterceptor = interceptor.NewDebugInterceptor(selectedInterceptor, flowRing)
		logger.Warn("FLOW INSPECTOR ENABLED — request bodies held in memory. Disable in production.")
	}

	p := &Proxy{
		config:       cfg,
		ca:           ca,
		certCache:    certCache,
		domainRouter: policy.NewDomainRouter(cfg.AllAIDomains()),
		vaultManager: vaultManager,
		engine:       sharedEngine,
		interceptor:  selectedInterceptor,
		flowRing:     flowRing,
		logger:       logger,
		startTime:    time.Now(),
		version:      version,
	}
	p.buildProviderCache()
	return p, nil
}

// buildProviderCache pre-computes the domain-to-provider mapping and sorted
// domain list for resolveProviderForHost. Called once during NewProxy.
// This avoids O(P×D + D log D) per-request rebuild (PR-003).
func (p *Proxy) buildProviderCache() {
	p.providerByDomain = make(map[string]string)
	var domains []providerDomain

	for name, provCfg := range p.config.Providers {
		if !provCfg.Enabled {
			continue
		}
		for _, domain := range provCfg.Domains {
			normalized := strings.ToLower(strings.TrimSpace(domain))
			if normalized == "" {
				continue
			}
			p.providerByDomain[normalized] = name
			domains = append(domains, providerDomain{domain: normalized, name: name})
		}
	}

	sort.Slice(domains, func(i, j int) bool {
		return len(domains[i].domain) > len(domains[j].domain)
	})
	p.providerSortedDomains = domains
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
func selectInterceptor(cfg *policy.Config, logger *slog.Logger, sharedEngine *pii.Engine) (Interceptor, error) {
	mode := cfg.Agent.Mode

	switch mode {
	case "transparent":
		return &NoOpInterceptor{}, nil

	case "monitor":
		engine := sharedEngine
		if engine == nil {
			engine = pii.NewEngine(pii.DefaultMaxInputBytes,
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
		}

		logger.Info("Monitor mode active: PII detection enabled, traffic passed through unmodified. PII still reaches AI providers. Use enforce mode to tokenize PII.",
			"pii_logging", cfg.Logging.PIILoggingValue(),
		)

		mi, err := interceptor.NewMonitorInterceptor(engine, cfg.Logging.PIILoggingValue(), logger, cfg.Agent.Monitor.ScanPaths)
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
		// Enforce mode: PII tokenization before egress + rehydration on ingress.
		engine := sharedEngine
		if engine == nil {
			engine = pii.NewEngine(pii.DefaultMaxInputBytes,
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
		}

		logger.Info("Enforce mode active: PII will be tokenized before egress and rehydrated on ingress. Zero PII leaves the machine.",
			"pii_logging", cfg.Logging.PIILoggingValue(),
			"fail_mode", cfg.Agent.FailModeValue(),
		)

		// Build provider registry for enforce mode.
		// Each provider gets an EnforceInterceptor instead of ProviderInterceptor.
		providerMap := buildEnforceRegistry(cfg, engine, logger)

		if len(providerMap) == 0 {
			// No provider plugins registered — use a basic EnforceInterceptor with full-body scanning.
			logger.Info("No provider plugins registered, using EnforceInterceptor for all domains")
			ei, err := interceptor.NewEnforceInterceptor(
				engine, nil, cfg.Logging.PIILoggingValue(), logger,
			)
			if err != nil {
				return nil, fmt.Errorf("creating enforce interceptor: %w", err)
			}
			return ei, nil
		}

		// Build a basic EnforceInterceptor as fallback for non-provider domains.
		fallbackEI, err := interceptor.NewEnforceInterceptor(
			engine, nil, cfg.Logging.PIILoggingValue(), logger,
		)
		if err != nil {
			return nil, fmt.Errorf("creating fallback enforce interceptor: %w", err)
		}

		logger.Info("Provider plugins registered for enforce mode",
			"domain_count", len(providerMap),
		)

		return &providerDispatcher{
			fallback:      fallbackEI,
			providers:     providerMap,
			sortedDomains: buildSortedDomains(providerMap),
			logger:        logger,
		}, nil

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

// providerDomain pairs a normalized domain with its provider name for
// resolveProviderForHost suffix matching (PR-003 cache).
type providerDomain struct {
	domain string
	name   string
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

// ShouldProcess routes to the interceptor matching the given host and delegates.
// This is needed by DebugInterceptor to avoid buffering bodies for endpoints
// that the inner interceptor will pass through unmodified.
func (d *providerDispatcher) ShouldProcess(host, method, path string) bool {
	ic := d.selectForHost(host)
	return ic.ShouldProcess(host, method, path)
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

// buildEnforceRegistry creates EnforceInterceptors for each enabled provider
// that has a registered plugin, for use in enforce mode.
func buildEnforceRegistry(cfg *policy.Config, engine *pii.Engine, logger *slog.Logger) map[string]Interceptor {
	registry := make(map[string]Interceptor)

	for name, provCfg := range cfg.Providers {
		if !provCfg.Enabled {
			continue
		}

		plugin := providers.Create(name, logger)
		if plugin == nil {
			continue
		}

		ei, err := interceptor.NewEnforceInterceptor(
			engine, plugin, cfg.Logging.PIILoggingValue(), logger,
		)
		if err != nil {
			logger.Warn("Failed to create EnforceInterceptor, skipping provider",
				"provider", name,
				"error", err,
			)
			continue
		}

		for _, domain := range provCfg.Domains {
			normalized := strings.ToLower(strings.TrimSpace(domain))
			if normalized == "" {
				continue
			}
			if _, exists := registry[normalized]; exists {
				logger.Warn("Domain conflict in enforce registry, last write wins",
					"domain", normalized,
					"current_provider", name,
				)
			}
			registry[normalized] = ei
			logger.Debug("Enforce interceptor registered",
				"provider", name,
				"domain", normalized,
			)
		}
	}

	return registry
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
			engine, plugin, cfg.Logging.PIILoggingValue(), logger,
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

// resolveProviderForHost determines which configured provider name corresponds
// to a given host. Uses pre-computed cache (built in NewProxy via buildProviderCache)
// to avoid O(n log n) per-request rebuild (PR-003).
//
// Matching: exact match first, then suffix match (longest domain first),
// defaulting to "unknown" if no match is found.
func (p *Proxy) resolveProviderForHost(host string) string {
	host = sanitizeHostForDispatch(host)
	if host == "" {
		return "unknown"
	}

	if len(p.providerByDomain) == 0 {
		return "unknown"
	}

	// Exact match.
	if name, ok := p.providerByDomain[host]; ok {
		return name
	}

	// Suffix match: sorted by domain length descending (pre-computed),
	// so more specific domains (api.openai.com) match before less specific (openai.com).
	for _, entry := range p.providerSortedDomains {
		if strings.HasSuffix(host, "."+entry.domain) {
			return entry.name
		}
	}

	return "unknown"
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

// handleHTTP processes non-CONNECT HTTP requests (PAC, health, debug).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// AC-2: /debug/flow must be localhost-only. The proxy already binds to
	// 127.0.0.1 per SR4 config validation, but we add a defense-in-depth
	// check here as well.
	switch r.URL.Path {
	case "/proxy.pac":
		p.handlePAC(w, r)
	case "/health":
		p.handleHealth(w, r)
	case "/debug/flow":
		if p.flowRing == nil {
			http.NotFound(w, r)
			return
		}
		// Defense-in-depth: verify request is from localhost.
		if !isLocalhostRequest(r) {
			p.logger.Warn("debug_flow_rejected",
				"reason", "non_localhost_request",
				"pii_values_logged", false,
			)
			http.Error(w, `{"error":"forbidden","detail":"localhost only"}`, http.StatusForbidden)
			return
		}
		interceptor.FlowHandler(p.flowRing)(w, r)
	default:
		http.NotFound(w, r)
	}
}

// isLocalhostRequest returns true if the request originated from localhost.
// Checks both the RemoteAddr and the X-Forwarded-For header (for defense in depth).
// The proxy binds to loopback per SR4, so remote connections are impossible.
func isLocalhostRequest(r *http.Request) bool {
	// Extract host from RemoteAddr (strip port if present).
	host := r.RemoteAddr
	if idx := strings.LastIndexByte(host, ':'); idx > 0 {
		host = host[:idx]
	}
	// Strip IPv6 brackets if present.
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
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
