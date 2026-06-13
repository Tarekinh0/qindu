package policy

import "strings"

// Action represents the routing decision for a hostname.
type Action string

const (
	// ActionMITM means the traffic should be decrypted and inspected.
	ActionMITM Action = "MITM"
	// ActionTunnel means the traffic should be forwarded without decryption.
	ActionTunnel Action = "Tunnel"
)

// DomainRouter decides whether to MITM or tunnel a given host.
type DomainRouter struct {
	aiDomains map[string]bool // lowercased AI domains
}

// NewDomainRouter creates a DomainRouter from a list of AI domains.
func NewDomainRouter(aiDomains []string) *DomainRouter {
	dm := make(map[string]bool, len(aiDomains))
	for _, d := range aiDomains {
		dm[strings.ToLower(d)] = true
	}
	return &DomainRouter{aiDomains: dm}
}

// Route returns the Action for a given hostname.
// Host is compared case-insensitively against the AI domain list.
// If the host is an exact match or a subdomain of a configured AI domain,
// it returns ActionMITM. Otherwise, it returns ActionTunnel.
func (r *DomainRouter) Route(host string) Action {
	host = strings.ToLower(host)

	// Check exact match first
	if r.aiDomains[host] {
		return ActionMITM
	}

	// Check subdomain match: "cdn.chatgpt.com" matches "chatgpt.com"
	for domain := range r.aiDomains {
		if strings.HasSuffix(host, "."+domain) {
			return ActionMITM
		}
	}

	return ActionTunnel
}

// IsAIDomain returns true if the host matches a configured AI domain.
func (r *DomainRouter) IsAIDomain(host string) bool {
	return r.Route(host) == ActionMITM
}
