package policy

import (
	"testing"
)

// TestDomainRouter_MITM verifies that AI domains are routed to MITM.
func TestDomainRouter_MITM(t *testing.T) {
	aiDomains := []string{"chatgpt.com", "claude.ai"}
	router := NewDomainRouter(aiDomains)

	tests := []struct {
		host   string
		action Action
	}{
		// Exact matches
		{"chatgpt.com", ActionMITM},
		{"claude.ai", ActionMITM},
		// Subdomain matches
		{"cdn.chatgpt.com", ActionMITM},
		{"api.chatgpt.com", ActionMITM},
		{"www.claude.ai", ActionMITM},
		// Non-AI domains
		{"google.com", ActionTunnel},
		{"example.com", ActionTunnel},
		{"github.com", ActionTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			action := router.Route(tt.host)
			if action != tt.action {
				t.Errorf("Route(%q) = %q, want %q", tt.host, action, tt.action)
			}
		})
	}
}

// TestDomainRouter_CaseInsensitive verifies case-insensitive matching.
func TestDomainRouter_CaseInsensitive(t *testing.T) {
	aiDomains := []string{"ChatGPT.com", "Claude.AI"}
	router := NewDomainRouter(aiDomains)

	tests := []struct {
		host   string
		action Action
	}{
		{"chatgpt.com", ActionMITM},
		{"CHATGPT.COM", ActionMITM},
		{"ChatGpt.Com", ActionMITM},
		{"CDN.CHATGPT.COM", ActionMITM},
		{"claude.ai", ActionMITM},
		{"CLAUDE.AI", ActionMITM},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			action := router.Route(tt.host)
			if action != tt.action {
				t.Errorf("Route(%q) = %q, want %q", tt.host, action, tt.action)
			}
		})
	}
}

// TestDomainRouter_DefaultTunnel verifies that the default route is Tunnel (not MITM).
// SR6: Configured AI domains are the only source of truth.
func TestDomainRouter_DefaultTunnel(t *testing.T) {
	aiDomains := []string{"chatgpt.com"}
	router := NewDomainRouter(aiDomains)

	// Non-AI and unknown domains must be Tunnel
	nonAIDomains := []string{
		"example.com",
		"google.com",
		"github.com",
		"bank.com",
		"internal.corp.net",
		"localhost",
		"aol.com", // historical, not AI
	}

	for _, host := range nonAIDomains {
		t.Run(host, func(t *testing.T) {
			action := router.Route(host)
			if action != ActionTunnel {
				t.Errorf("Route(%q) = %q, want Tunnel (default)", host, action)
			}
		})
	}
}

// TestDomainRouter_DomainInjection verifies SR6/SEC-T6: prevents domain injection attacks.
// SR6: No request-controlled routing overrides.
func TestDomainRouter_DomainInjection(t *testing.T) {
	aiDomains := []string{"chatgpt.com"}
	router := NewDomainRouter(aiDomains)

	// Attempts to trick the router should all result in Tunnel
	attackDomains := []string{
		"chatgpt.com.malicious.net",  // Different domain ending in chatgpt.com
		"chatgpt.com.evil.com",       // Subdomain trick
		"notchatgpt.com",             // Similar name but not match
		"chatgpt.com\nX-Inject:true", // Injection attempt
		"",                           // Empty host
	}

	for _, host := range attackDomains {
		t.Run(host, func(t *testing.T) {
			action := router.Route(host)
			if action != ActionTunnel {
				t.Errorf("injection attempt %q was routed to %q, should be Tunnel", host, action)
			}
		})
	}
}

// TestDomainRouter_EmptyDomainList verifies behavior with no AI domains.
func TestDomainRouter_EmptyDomainList(t *testing.T) {
	router := NewDomainRouter([]string{})

	hosts := []string{"chatgpt.com", "example.com", "google.com"}
	for _, host := range hosts {
		action := router.Route(host)
		if action != ActionTunnel {
			t.Errorf("Route(%q) with empty AI list = %q, want Tunnel", host, action)
		}
	}
}

// TestDomainRouter_IsAIDomain verifies the helper method.
func TestDomainRouter_IsAIDomain(t *testing.T) {
	aiDomains := []string{"chatgpt.com"}
	router := NewDomainRouter(aiDomains)

	if !router.IsAIDomain("chatgpt.com") {
		t.Error("chatgpt.com should be AI domain")
	}
	if !router.IsAIDomain("cdn.chatgpt.com") {
		t.Error("cdn.chatgpt.com should be AI domain (subdomain)")
	}
	if router.IsAIDomain("example.com") {
		t.Error("example.com should NOT be AI domain")
	}
}
