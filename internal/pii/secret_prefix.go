package pii

import (
	"regexp"
	"sort"
	"strings"
)

// secretPrefixEntry defines a known secret pattern with its prefix and
// associated regex for full token extraction.
//
// Provenance: Curated from GitGuardian taxonomy and Gitleaks default config.
// No actual secrets are hardcoded — only prefix strings and format patterns.
type secretPrefixEntry struct {
	re         *regexp.Regexp
	prefix     string  // Case-sensitive prefix string
	confidence float64 // Base confidence for this pattern
}

// secretPrefixes contains ~100 known API key/token prefix patterns organized
// by provider. Sorted by prefix length descending to ensure longest-prefix-first
// matching (prevents e.g., `sk-` from matching before `sk-proj-`).
//
//nolint:lll
var secretPrefixPatterns = []struct {
	prefix     string
	pattern    string
	confidence float64
}{
	// AI/ML Providers
	{"sk-proj-", `sk-proj-[A-Za-z0-9_-]{32,256}`, 0.85},
	{"sk-svcacct-", `sk-svcacct-[A-Za-z0-9_-]{32,256}`, 0.85},
	{"sk-admin-", `sk-admin-[A-Za-z0-9_-]{32,256}`, 0.85},
	{"sk-ant-api03-", `sk-ant-api03-[A-Za-z0-9_-]{95,192}AA`, 0.85},
	{"sk-ant-admin01-", `sk-ant-admin01-[A-Za-z0-9_-]{95,192}AA`, 0.85},
	{"sk_live_", `sk_live_[0-9a-zA-Z]{24,128}`, 0.85},
	{"pk_live_", `pk_live_[0-9a-zA-Z]{24,128}`, 0.85},
	{"sk_test_", `sk_test_[0-9a-zA-Z]{24,128}`, 0.85},
	{"pk_test_", `pk_test_[0-9a-zA-Z]{24,128}`, 0.85},
	{"whsec_", `whsec_[0-9a-zA-Z]{32,128}`, 0.85},
	{"sk-", `sk-[A-Za-z0-9]{32,256}`, 0.70}, // Generic OpenAI legacy (lower confidence without sub-prefix)
	{"hf_", `hf_[A-Za-z0-9]{34}`, 0.85},
	{"r8_", `r8_[A-Za-z0-9]{30,128}`, 0.85},
	{"dapi", `dapi[a-f0-9]{32}(-\d)?`, 0.85},

	// Cloud Providers
	{"AKIA", `AKIA[A-Z2-7]{16}`, 0.85},
	{"ASIA", `ASIA[A-Z2-7]{16}`, 0.85},
	{"ABIA", `ABIA[A-Z2-7]{16}`, 0.85},
	{"ACCA", `ACCA[A-Z2-7]{16}`, 0.85},
	{"ABSK", `ABSK[A-Za-z0-9+/]{109,269}={0,2}`, 0.85},
	{"AIza", `AIza[\w-]{35}`, 0.85},
	{"doo_v1_", `doo_v1_[a-f0-9]{64}`, 0.85},
	{"dop_v1_", `dop_v1_[a-f0-9]{64}`, 0.85},
	{"dor_v1_", `dor_v1_[a-f0-9]{64}`, 0.85},
	{"LTAI", `LTAI[a-z0-9]{20}`, 0.85},

	// Version Control (GitHub)
	{"github_pat_", `github_pat_[A-Za-z0-9_]{22,82}`, 0.85},
	{"ghp_", `ghp_[A-Za-z0-9]{36}`, 0.85},
	{"gho_", `gho_[A-Za-z0-9]{36}`, 0.85},
	{"ghu_", `ghu_[A-Za-z0-9]{36}`, 0.85},
	{"ghs_", `ghs_[A-Za-z0-9]{36}`, 0.85},
	{"ghr_", `ghr_[A-Za-z0-9]{36}`, 0.85},

	// Version Control (GitLab)
	{"glsoat-", `glsoat-[A-Za-z0-9_\-]{20,128}`, 0.85},
	{"glpat-", `glpat-[A-Za-z0-9_\-]{20,128}`, 0.85},
	{"gldt-", `gldt-[A-Za-z0-9_\-]{20,128}`, 0.85},
	{"glft-", `glft-[A-Za-z0-9_\-]{20,128}`, 0.85},
	{"glrt-", `glrt-[A-Za-z0-9_\-]{20,128}`, 0.85},

	// Version Control (Other)
	{"akcp", `AKCp[A-Za-z0-9]{69}`, 0.85},
	{"cmVmd", `cmVmd[A-Za-z0-9]{59}`, 0.85},

	// Messaging / Collaboration
	{"xoxb-", `xoxb-\d{10,12}-\d{10,12}-[A-Za-z0-9]+`, 0.85},
	{"xoxp-", `xoxp-\d{10,12}-\d{10,12}-[A-Za-z0-9]+`, 0.85},
	{"xoxa-", `xoxa-\d{10,12}-\d{10,12}-[A-Za-z0-9]+`, 0.85},
	{"xoxr-", `xoxr-\d{10,12}-\d{10,12}-[A-Za-z0-9]+`, 0.85},
	{"SG.", `SG\.[A-Za-z0-9_\-]{22,68}`, 0.85},
	{"key-", `key-[a-f0-9]{32}`, 0.85},
	{"EAA", `EAA[MC][a-z0-9]{100,512}`, 0.85},
	{"dt0c01.", `dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}`, 0.85},

	// Fly.io
	{"fm2_", `fm2_[A-Za-z0-9+/]{100,256}={0,3}`, 0.85},
	{"fm1", `fm1[ar]_[A-Za-z0-9+/]{100,256}={0,3}`, 0.85},
	{"fo1_", `fo1_[A-Za-z0-9_-]{43}`, 0.85},

	// CI/CD
	{"pt-", `pt-[A-Za-z0-9]{40}`, 0.85},

	// Payments (Square)
	{"sq0atp-", `sq0atp-[A-Za-z0-9_\-]{22}`, 0.85},
	{"sq0csp-", `sq0csp-[A-Za-z0-9_\-]{22}`, 0.85},

	// Payments (Razorpay)
	{"rzp_live_", `rzp_live_[A-Za-z0-9]{14}`, 0.85},
	{"rzp_test_", `rzp_test_[A-Za-z0-9]{14}`, 0.85},

	// Security / Secret Management
	{"ops_", `ops_eyJ[A-Za-z0-9+/]{250,512}={0,3}`, 0.85},
	{"A3-", `A3-[A-Z0-9]{6}-[A-Z0-9]{6,11}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`, 0.85},
	{"dp.pt.", `dp\.pt\.[a-z0-9]{43}`, 0.85},
	{"SNYK-", `SNYK-[A-Za-z0-9_-]{36}`, 0.85},
	{"sqp_", `sqp_[a-f0-9]{40}`, 0.85},

	// Other Common
	{"ntn_", `ntn_[A-Za-z0-9]{32,128}`, 0.85},
	{"figd_", `figd_[A-Za-z0-9_-]{28,128}`, 0.85},
	{"npm_", `npm_[A-Za-z0-9]{36}`, 0.85},
	{"pypi-", `pypi-[A-Za-z0-9_]{36,128}`, 0.85},
	{"v1.0-", `v1\.0-[a-f0-9]{24}-[a-f0-9]{146}`, 0.85},

	// Database connection strings
	{"mongodb+srv://", `mongodb\+srv://[^@\s]+@`, 0.85},
	{"postgresql://", `postgresql://[^@\s:]+:[^@\s]+@`, 0.85},
	{"mysql://", `mysql://[^@\s:]+:[^@\s]+@`, 0.85},
	{"redis://", `redis://[^@\s:]+(:[^@\s]+)?@`, 0.85},

	// Twilio (must come before generic AC/SK)
	{"AC", `AC[a-f0-9]{32}`, 0.85},
	{"SK", `SK[a-f0-9]{32}`, 0.85},

	// Telegram Bot (very short prefix, low confidence risk)
	{"T", `T[0-9]{8,10}:[A-Za-z0-9_-]{35}`, 0.85},

	// Buildkite
	// Already defined above as "pt-"
}

// SecretPrefixRecognizer detects API keys and tokens using a compiled-in
// database of known prefix patterns.
type SecretPrefixRecognizer struct {
	prefixMap     map[string][]secretPrefixEntry // O(1) lookup by prefix
	entries       []secretPrefixEntry
	prefixLengths []int // Sorted slice of unique prefix lengths for window scanning
	minPrefixLen  int
}

// NewSecretPrefixRecognizer creates a new prefix-based SECRET recognizer.
// Entries are sorted by prefix length descending to ensure longest-prefix-first
// matching (SEC-REQ-13).
func NewSecretPrefixRecognizer() *SecretPrefixRecognizer {
	// Sort patterns by prefix length descending.
	sorted := make([]struct {
		prefix     string
		pattern    string
		confidence float64
	}, len(secretPrefixPatterns))
	copy(sorted, secretPrefixPatterns)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].prefix) > len(sorted[j].prefix)
	})

	// Compile all entries.
	entries := make([]secretPrefixEntry, len(sorted))
	prefixMap := make(map[string][]secretPrefixEntry)
	prefixLenSet := make(map[int]bool)
	minPrefixLen := -1

	for i, p := range sorted {
		entry := secretPrefixEntry{
			prefix:     p.prefix,
			re:         regexp.MustCompile(p.pattern),
			confidence: p.confidence,
		}
		entries[i] = entry
		prefixMap[p.prefix] = append(prefixMap[p.prefix], entry)
		prefixLenSet[len(p.prefix)] = true
		if minPrefixLen == -1 || len(p.prefix) < minPrefixLen {
			minPrefixLen = len(p.prefix)
		}
	}

	// Build sorted list of prefix lengths for window scanning.
	prefixLengths := make([]int, 0, len(prefixLenSet))
	for l := range prefixLenSet {
		prefixLengths = append(prefixLengths, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(prefixLengths)))

	return &SecretPrefixRecognizer{
		entries:       entries,
		prefixLengths: prefixLengths,
		prefixMap:     prefixMap,
		minPrefixLen:  minPrefixLen,
	}
}

// Type returns SECRET.
func (r *SecretPrefixRecognizer) Type() EntityType {
	return Secret
}

// Detect finds all secret tokens matching known prefix patterns.
func (r *SecretPrefixRecognizer) Detect(text string) []Entity {
	if len(text) < r.minPrefixLen {
		return nil
	}

	var entities []Entity

	// For each position, check all known prefixes by scanning prefix lengths.
	for i := 0; i < len(text); {
		found := false
		for _, plen := range r.prefixLengths {
			if i+plen > len(text) {
				continue
			}
			prefixCandidate := text[i : i+plen]
			entries, ok := r.prefixMap[prefixCandidate]
			if !ok {
				continue
			}
			for _, entry := range entries {
				// Full regex match from this position.
				loc := entry.re.FindStringIndex(text[i:])
				if loc == nil || loc[0] != 0 {
					continue
				}
				matchEnd := i + loc[1]

				// Skip URL contexts for secret detection.
				if isURLContext(text, i) {
					continue
				}

				entities = append(entities, Entity{
					Type:       Secret,
					Value:      text[i:matchEnd],
					Confidence: entry.confidence,
					Source:     SourcePrefix,
					Start:      i,
					End:        matchEnd,
				})
				found = true
				break // Move past this match.
			}
			if found {
				break
			}
		}
		if found {
			// Skip past the matched portion.
			// Since we break after first match at this position, advance past it.
			i = entities[len(entities)-1].End
		} else {
			i++
		}
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// isURLContext checks if a position in text appears to be within a URL context
// (e.g., https://...?token=value). This prevents false positives in URLs.
// Checks up to 2000 characters preceding the position for a URL scheme.
func isURLContext(text string, pos int) bool {
	// Look backwards up to 2000 chars for http:// or https://.
	start := pos - 2000
	if start < 0 {
		start = 0
	}
	preceding := text[start:pos]
	if strings.Contains(preceding, "https://") || strings.Contains(preceding, "http://") {
		return true
	}
	return false
}
