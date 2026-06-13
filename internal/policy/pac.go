package policy

import (
	"strings"
)

// pacTemplate is the JavaScript PAC template.
// The domains are injected at generation time.
const pacTemplate = `// Qindu AI Privacy Proxy - PAC file
// Generated automatically from config. Do not edit manually.

function FindProxyForURL(url, host) {
    // AI provider domains - route through Qindu for PII protection
    var aiDomains = [
        {{.Domains}}
    ];

    // Check if host matches any AI domain
    for (var i = 0; i < aiDomains.length; i++) {
        if (dnsDomainIs(host, aiDomains[i]) ||
            shExpMatch(host, "*." + aiDomains[i])) {
            return "PROXY {{.ProxyAddr}}";
        }
    }

    // All other traffic goes directly
    return "DIRECT";
}
`

// GeneratePAC produces a PAC JavaScript string from the given AI domains and proxy address.
// The output is valid PAC JavaScript suitable for browser auto-configuration.
func GeneratePAC(aiDomains []string, proxyAddr string) string {
	// Build the JavaScript array of domain strings
	quoted := make([]string, len(aiDomains))
	for i, d := range aiDomains {
		quoted[i] = `"` + d + `"`
	}

	domainsJS := strings.Join(quoted, ",\n        ")

	script := strings.Replace(pacTemplate, "{{.Domains}}", domainsJS, 1)
	script = strings.Replace(script, "{{.ProxyAddr}}", proxyAddr, 1)

	return script
}
