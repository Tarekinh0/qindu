package pii

import (
	"regexp"
	"strings"
)

// ccPattern defines a known credit card issuer pattern.
type ccPattern struct {
	name     string
	prefixes []string
	minLen   int
	maxLen   int
}

// creditCardPatterns defines known credit card issuer patterns with BIN prefixes
// and expected lengths.
var creditCardPatterns = []ccPattern{
	{
		name:     "Visa",
		minLen:   13,
		maxLen:   19,
		prefixes: []string{"4"},
	},
	{
		name:   "Mastercard",
		minLen: 16,
		maxLen: 16,
		prefixes: []string{
			"51", "52", "53", "54", "55",
			"2221", "2222", "2223", "2224", "2225",
			"2226", "2227", "2228", "2229", "223",
			"224", "225", "226", "227", "228", "229",
			"23", "24", "25", "26", "270", "271", "2720",
		},
	},
	{
		name:     "American Express",
		minLen:   15,
		maxLen:   15,
		prefixes: []string{"34", "37"},
	},
	{
		name:     "Discover",
		minLen:   16,
		maxLen:   19,
		prefixes: []string{"6011", "644", "645", "646", "647", "648", "649", "65"},
	},
	{
		name:     "Diners Club",
		minLen:   14,
		maxLen:   19,
		prefixes: []string{"300", "301", "302", "303", "304", "305", "36", "38", "39"},
	},
}

// CreditCardRecognizer detects credit card numbers using BIN prefix matching
// and Luhn checksum validation.
type CreditCardRecognizer struct {
	re *regexp.Regexp
}

// NewCreditCardRecognizer creates a new CREDIT_CARD recognizer.
func NewCreditCardRecognizer() *CreditCardRecognizer {
	// Match 13-19 digit sequences, allowing common separators (spaces, dashes).
	return &CreditCardRecognizer{
		re: regexp.MustCompile(`\b[0-9][0-9 .-]{11,}[0-9]\b`),
	}
}

// Type returns CREDIT_CARD.
func (r *CreditCardRecognizer) Type() EntityType {
	return CreditCard
}

// Detect finds all credit card numbers in the given text.
func (r *CreditCardRecognizer) Detect(text string) []Entity {
	matches := r.re.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	entities := make([]Entity, 0, len(matches))
	for _, m := range matches {
		candidate := text[m[0]:m[1]]
		result := validateCreditCard(candidate)
		if result.confidence == 0 {
			continue
		}
		entities = append(entities, Entity{
			Type:       CreditCard,
			Value:      candidate,
			Confidence: result.confidence,
			Source:     SourceLuhn,
			Start:      m[0],
			End:        m[1],
		})
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

type ccValidationResult struct {
	confidence float64
}

// validateCreditCard checks if a string is a valid credit card number.
func validateCreditCard(s string) ccValidationResult {
	// Extract digits only.
	digits := extractDigitsCC(s)
	digitCount := len(digits)

	if digitCount < 13 || digitCount > 19 {
		return ccValidationResult{}
	}

	// Check issuer prefix.
	if !matchesAnyPrefix(digits, creditCardPatterns) {
		return ccValidationResult{}
	}

	// Luhn checksum.
	if luhnCheck(digits) {
		return ccValidationResult{confidence: 0.95}
	}

	// Luhn failed but structure matches — lower confidence.
	return ccValidationResult{confidence: 0.85}
}

// extractDigitsCC extracts digits from a credit card string.
func extractDigitsCC(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// matchesAnyPrefix checks if the digit string starts with any known issuer prefix.
func matchesAnyPrefix(digits string, patterns []ccPattern) bool {
	for _, p := range patterns {
		if len(digits) < p.minLen || len(digits) > p.maxLen {
			continue
		}
		for _, prefix := range p.prefixes {
			if len(prefix) > len(digits) {
				continue
			}
			if digits[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// luhnCheck validates a string of digits using the Luhn algorithm (MOD-10).
func luhnCheck(digits string) bool {
	n := len(digits)
	if n < 2 {
		return false
	}

	sum := 0
	double := false

	// Process from right to left.
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}

	return sum%10 == 0
}
