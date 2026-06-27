package pii

import (
	"regexp"
	"strings"
)

// secretKeywords is a list of secret-related keywords used for pre-filtering
// before expensive entropy calculation. Case-insensitive matching.
// If no keyword is found within a 100-char window, the window is skipped.
var secretKeywords = []string{
	"api_key", "apikey", "api-key", "api_secret", "apisecret",
	"access_key", "accesskey", "access_token", "accesstoken",
	"auth_token", "authtoken", "bearer_token", "bearertoken",
	"client_secret", "clientsecret", "consumer_key", "consumerkey",
	"credential", "encryption_key", "encryptionkey", "license_key",
	"licensekey", "passwd", "password", "private_key", "privatekey",
	"refresh_token", "refreshtoken", "secret", "secret_key",
	"secretkey", "session_key", "sessionkey", "token",
	"webhook_secret", "webhooksecret",
}

// entropyPatterns holds the compiled regexes for the multi-layered entropy detection.
type entropyPatterns struct {
	base64Candidate *regexp.Regexp // [A-Za-z0-9+/]{20,}={0,2}
	hexCandidate    *regexp.Regexp // [0-9a-fA-F]{32,}
	bearerToken     *regexp.Regexp // (?i)bearer\s+([A-Za-z0-9_\-.+/=]{20,})
	keyValueAssign  *regexp.Regexp // Key-value assignment pattern
}

// base64Alphabet is the set of characters valid in base64.
var base64Alphabet = func() map[byte]bool {
	m := make(map[byte]bool, 66)
	for c := 'A'; c <= 'Z'; c++ {
		m[byte(c)] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		m[byte(c)] = true
	}
	for c := '0'; c <= '9'; c++ {
		m[byte(c)] = true
	}
	m['+'] = true
	m['/'] = true
	m['='] = true
	return m
}()

// hexAlphabet is the set of characters valid in hex.
var hexAlphabet = func() map[byte]bool {
	m := make(map[byte]bool, 22)
	for c := '0'; c <= '9'; c++ {
		m[byte(c)] = true
	}
	for c := 'A'; c <= 'F'; c++ {
		m[byte(c)] = true
	}
	for c := 'a'; c <= 'f'; c++ {
		m[byte(c)] = true
	}
	return m
}()

// SecretEntropyRecognizer detects high-entropy strings that are likely secrets
// even without a known prefix. Uses multi-layered detection:
//
//	Layer 0: Keyword pre-filter
//	Layer 1: Base64-like strings with entropy ≥ 3.5
//	Layer 2: Hex strings with entropy ≥ 3.0
//	Layer 3: Bearer/Authorization tokens
//	Layer 4: Key-value assignment patterns
type SecretEntropyRecognizer struct {
	patterns entropyPatterns
}

// NewSecretEntropyRecognizer creates a new generic entropy SECRET recognizer.
func NewSecretEntropyRecognizer() *SecretEntropyRecognizer {
	return &SecretEntropyRecognizer{
		patterns: entropyPatterns{
			base64Candidate: regexp.MustCompile(`[A-Za-z0-9+/]{20,256}={0,2}`),
			hexCandidate:    regexp.MustCompile(`[0-9a-fA-F]{32,256}`),
			bearerToken:     regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9_\-\.\+/=]{20,256})`),
			keyValueAssign:  regexp.MustCompile(`(?i)(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:=|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})`),
		},
	}
}

// Type returns SECRET.
func (r *SecretEntropyRecognizer) Type() EntityType {
	return Secret
}

// Detect finds high-entropy strings that are likely secrets.
func (r *SecretEntropyRecognizer) Detect(text string) []Entity {
	if len(text) == 0 {
		return nil
	}

	// Layer 0: Keyword pre-filter.
	if !containsKeyword(text) {
		return nil
	}

	var entities []Entity
	seen := make(map[[2]int]bool)

	// Layer 1: Base64-like strings.
	for _, m := range r.patterns.base64Candidate.FindAllStringIndex(text, -1) {
		candidate := text[m[0]:m[1]]
		if isFalsePositive(candidate) {
			continue
		}
		span := [2]int{m[0], m[1]}
		entropy := ComputeEntropyOverAlphabet(candidate, base64Alphabet)
		var confidence float64
		if entropy >= 4.5 {
			confidence = 0.80
		} else if entropy >= 3.5 {
			confidence = 0.70
		} else {
			continue
		}
		seen[span] = true
		entities = append(entities, Entity{
			Type:       Secret,
			Value:      candidate,
			Confidence: confidence,
			Source:     SourceEntropy,
			Start:      m[0],
			End:        m[1],
		})
	}

	// Layer 2: Hex strings.
	for _, m := range r.patterns.hexCandidate.FindAllStringIndex(text, -1) {
		candidate := text[m[0]:m[1]]
		if isFalsePositive(candidate) {
			continue
		}
		span := [2]int{m[0], m[1]}
		if seen[span] {
			continue
		}
		entropy := ComputeEntropyOverAlphabet(candidate, hexAlphabet)
		if entropy < 3.0 {
			continue
		}
		seen[span] = true
		entities = append(entities, Entity{
			Type:       Secret,
			Value:      candidate,
			Confidence: 0.65,
			Source:     SourceEntropy,
			Start:      m[0],
			End:        m[1],
		})
	}

	// Layer 3: Bearer/Authorization tokens.
	for _, m := range r.patterns.bearerToken.FindAllStringSubmatchIndex(text, -1) {
		// m[0], m[1] = full match; m[2], m[3] = capture group 1 (the token)
		if len(m) >= 4 {
			tokenStart, tokenEnd := m[2], m[3]
			span := [2]int{tokenStart, tokenEnd}
			if seen[span] {
				continue
			}
			if isFalsePositive(text[tokenStart:tokenEnd]) {
				continue
			}
			seen[span] = true
			entities = append(entities, Entity{
				Type:       Secret,
				Value:      text[tokenStart:tokenEnd],
				Confidence: 0.50,
				Source:     SourceEntropy,
				Start:      tokenStart,
				End:        tokenEnd,
			})
		}
	}

	// Layer 4: Key-value assignment patterns.
	for _, m := range r.patterns.keyValueAssign.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 4 {
			valStart, valEnd := m[2], m[3]
			candidate := text[valStart:valEnd]
			span := [2]int{valStart, valEnd}
			if seen[span] {
				continue
			}
			if isFalsePositive(candidate) {
				continue
			}
			// Validate with entropy for the assignment value.
			entropy := ComputeEntropy(candidate)
			if entropy < 3.5 {
				continue
			}
			seen[span] = true
			entities = append(entities, Entity{
				Type:       Secret,
				Value:      candidate,
				Confidence: 0.60,
				Source:     SourceEntropy,
				Start:      valStart,
				End:        valEnd,
			})
		}
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// containsKeyword checks if the text contains any secret-related keyword
// (case-insensitive). This is the Layer 0 pre-filter to avoid expensive
// entropy calculation on non-secret text.
func containsKeyword(text string) bool {
	lower := strings.ToLower(text)
	for _, kw := range secretKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isFalsePositive checks if a candidate string is a known false positive
// (UUID, hash, placeholder, etc.).
func isFalsePositive(s string) bool {
	if len(s) == 0 {
		return true
	}

	// Check placeholder values.
	lower := strings.ToLower(s)
	placeholders := []string{"true", "false", "null", "undefined", "example", "test", "demo", "sample"}
	for _, p := range placeholders {
		if lower == p {
			return true
		}
	}

	// Check if it looks like a UUID.
	if isUUIDFormat(s) {
		return true
	}

	// Check if it's an exact-length hex hash.
	if isHexHash(s) {
		return true
	}

	// Check ALL_CAPS identifiers (environment variable names).
	if isAllCapsIdentifier(s) {
		return true
	}

	return false
}

// isUUIDFormat checks if a string matches UUID format (8-4-4-4-12 hex).
func isUUIDFormat(s string) bool {
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// isHexHash checks if a string is exactly a known hash length hex string.
func isHexHash(s string) bool {
	knownLengths := map[int]bool{32: true, 40: true, 64: true, 128: true}
	if !knownLengths[len(s)] {
		return false
	}
	for _, c := range s {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// isHexDigit returns true if the rune is a hexadecimal digit (0-9, a-f, A-F).
func isHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isAllCapsIdentifier checks if a string is an all-caps identifier with underscores.
func isAllCapsIdentifier(s string) bool {
	if len(s) < 3 || len(s) > 30 {
		return false
	}
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || c == '_' {
			continue
		}
		return false
	}
	return true
}
