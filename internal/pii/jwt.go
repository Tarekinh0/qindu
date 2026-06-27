package pii

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// jwtMaxLength is the maximum length for a detected JWT token.
const jwtMaxLength = 8192

// jwtPattern matches three base64url segments separated by dots.
// Simplified: [A-Za-z0-9_-] + dot + [A-Za-z0-9_-] + dot + [A-Za-z0-9_-]
//
//nolint:lll
const jwtPatternSrc = `[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`

// JWTRecognizer detects JSON Web Tokens by structural analysis.
type JWTRecognizer struct {
	re *regexp.Regexp
}

// NewJWTRecognizer creates a new JWT recognizer.
func NewJWTRecognizer() *JWTRecognizer {
	return &JWTRecognizer{
		re: regexp.MustCompile(jwtPatternSrc),
	}
}

// Type returns JWT.
func (r *JWTRecognizer) Type() EntityType {
	return JWT
}

// Detect finds all JWT tokens in the given text.
func (r *JWTRecognizer) Detect(text string) []Entity {
	matches := r.re.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	entities := make([]Entity, 0, len(matches))
	for _, m := range matches {
		candidate := text[m[0]:m[1]]

		// Bounds check.
		if len(candidate) > jwtMaxLength {
			continue
		}

		// Right boundary: char after match must not be a dot or base64url char.
		// This prevents matching "one.two.three" from "one.two.three.four".
		if m[1] < len(text) && (text[m[1]] == '.' || isBase64URLChar(text[m[1]])) {
			continue
		}

		// Must have exactly 2 dots (3 segments).
		// Guaranteed by regex: pattern matches exactly three
		// base64url segments separated by two dots.
		segments := strings.SplitN(candidate, ".", 3)
		// len(segments) is always 3 due to regex structure.
		// All segments are non-empty due to + quantifier in regex.

		// Validate first segment is base64url-encoded valid JSON with "alg" field.
		confidence := validateJWTSegment(segments[0])
		if confidence < 0.60 {
			continue
		}

		entities = append(entities, Entity{
			Type:       JWT,
			Value:      candidate,
			Confidence: confidence,
			Source:     SourceStructural,
			Start:      m[0],
			End:        m[1],
		})
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// isBase64URLChar returns true if the byte is a valid base64url character.
func isBase64URLChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
}

// validateJWTSegment base64url-decodes a JWT header segment and checks it
// contains valid JSON with an "alg" field.
func validateJWTSegment(segment string) float64 {
	// base64url decode (with padding adjustment).
	decoded, err := base64URLDecode(segment)
	if err != nil || len(decoded) == 0 {
		// Not valid base64url — too unlikely to be a JWT.
		return 0.55
	}

	// Check if it's valid JSON.
	if !json.Valid(decoded) {
		return 0.55
	}

	// Check for "alg" field.
	var header map[string]interface{}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return 0.55
	}

	if _, hasAlg := header["alg"]; hasAlg {
		return 0.90
	}

	// Header is valid JSON but no "alg" field.
	return 0.80
}

// base64URLDecode decodes a base64url-encoded string (without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed.
	padding := len(s) % 4
	if padding > 0 {
		s += strings.Repeat("=", 4-padding)
	}
	return base64.URLEncoding.DecodeString(s)
}
