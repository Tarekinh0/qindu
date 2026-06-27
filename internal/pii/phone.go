package pii

import (
	"regexp"
	"strings"
)

// phonePatterns is the list of compiled regex patterns for phone detection.
// Each pattern covers a different phone number format.
//
// All quantifiers use bounded digit counts to prevent ReDoS.
// Go's RE2 engine guarantees linear-time matching regardless.
var phonePatternSources = []string{
	// FR format: +33 X XX XX XX XX with various separators
	`\+33[\s.-]?[1-9](?:[\s.-]?\d{1,2}){4}`,
	// FR format: 0X XX XX XX XX (French leading zero)
	`0[1-9](?:[\s.-]?\d{2}){4}`,
	// International E.164: +XX ... with 7-15 digits total
	// Supports spaces/dots/dashes between digit groups.
	`\+[1-9][0-9]{0,2}(?:[\s.-]?[0-9]+)+`,
	// US/CA NANP: +1 (XXX) XXX-XXXX or (XXX) XXX-XXXX
	`\+1[\s.-]?\([0-9]{3}\)[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}`,
	// US/CA NANP: XXX-XXX-XXXX or XXX.XXX.XXXX
	`\(?[0-9]{3}\)?[\s.-][0-9]{3}[\s.-][0-9]{4}`,
}

// PhoneRecognizer detects phone numbers in text.
type PhoneRecognizer struct {
	res []*regexp.Regexp
}

// NewPhoneRecognizer creates a new PHONE recognizer.
func NewPhoneRecognizer() *PhoneRecognizer {
	res := make([]*regexp.Regexp, len(phonePatternSources))
	for i, pat := range phonePatternSources {
		res[i] = regexp.MustCompile(pat)
	}
	return &PhoneRecognizer{res: res}
}

// Type returns PHONE.
func (r *PhoneRecognizer) Type() EntityType {
	return Phone
}

// Detect finds all phone numbers in the given text.
func (r *PhoneRecognizer) Detect(text string) []Entity {
	var entities []Entity
	seen := make(map[[2]int]bool) // Deduplicate by span.

	for _, re := range r.res {
		matches := re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			span := [2]int{m[0], m[1]}
			if seen[span] {
				continue
			}
			seen[span] = true

			candidate := text[m[0]:m[1]]
			confidence := validatePhoneNumber(candidate)
			if confidence < 0.55 {
				// Below minimum confidence threshold, skip.
				continue
			}
			entities = append(entities, Entity{
				Type:       Phone,
				Value:      candidate,
				Confidence: confidence,
				Source:     SourceRegex,
				Start:      m[0],
				End:        m[1],
			})
		}
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// validatePhoneNumber checks a phone number candidate and returns a confidence score.
func validatePhoneNumber(phone string) float64 {
	// Extract just the digits.
	digits := extractDigits(phone)
	digitCount := len(digits)

	// Digit count validation: 7-15 digits.
	if digitCount < 7 || digitCount > 15 {
		return 0.50
	}

	// Must not be all same digit (e.g., 000-000-0000).
	if isAllSameDigit(digits) {
		return 0.55
	}

	// Check for sequential patterns (low confidence downgrade).
	if isSequential(digits) {
		return 0.60
	}

	// Basic regex match alone.
	confidence := 0.75

	// Validated digit count bumps confidence.
	if digitCount >= 7 && digitCount <= 15 {
		confidence = 0.85
	}

	return confidence
}

// extractDigits extracts all digit characters from a string.
func extractDigits(s string) string {
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

// isAllSameDigit checks if all characters in a string are the same digit.
func isAllSameDigit(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// isSequential checks if a digit string contains a significant run of consecutive
// digits (ascending or descending). A run of 3 or more consecutive digits in
// either direction triggers a downgrade.
//
// This handles grouped patterns like "123-456-7890" (which becomes "1234567890"
// after extracting digits) where the digit string is not entirely sequential
// (wraps at 9→0) but contains long consecutive runs.
func isSequential(digits string) bool {
	if len(digits) < 3 {
		return false
	}

	maxAsc, maxDesc := 1, 1
	curAsc, curDesc := 1, 1

	for i := 1; i < len(digits); i++ {
		switch digits[i] {
		case digits[i-1] + 1:
			curAsc++
			curDesc = 1
		case digits[i-1] - 1:
			curDesc++
			curAsc = 1
		default:
			curAsc = 1
			curDesc = 1
		}
		if curAsc > maxAsc {
			maxAsc = curAsc
		}
		if curDesc > maxDesc {
			maxDesc = curDesc
		}
	}

	return maxAsc >= 3 || maxDesc >= 3
}
