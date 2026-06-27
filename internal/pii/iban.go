package pii

import (
	"regexp"
	"strings"
)

// ibanCountryPatterns maps country codes to their IBAN regex patterns and
// expected lengths. Only EU/EEA + CH/MC/SM/AD country codes are included.
var ibanCountryPatterns = []struct {
	regex  string
	code   string
	length int
}{
	{`DE\d{20}`, "DE", 22},
	{`FR\d{12}[A-Z0-9]{11}\d{2}`, "FR", 27},
	{`GB\d{2}[A-Z]{4}\d{14}`, "GB", 22},
	{`ES\d{22}`, "ES", 24},
	{`IT\d{2}[A-Z]\d{10}[A-Z0-9]{12}`, "IT", 27},
	{`NL\d{2}[A-Z]{4}\d{10}`, "NL", 18},
	{`BE\d{14}`, "BE", 16},
	{`CH\d{7}[A-Z0-9]{12}`, "CH", 21},
	{`AT\d{18}`, "AT", 20},
	{`PT\d{23}`, "PT", 25},
	{`IE\d{2}[A-Z]{4}\d{14}`, "IE", 22},
	{`LU\d{5}[A-Z0-9]{13}`, "LU", 20},
	{`GR\d{9}[A-Z0-9]{16}`, "GR", 27},
	{`FI\d{16}`, "FI", 18},
	{`DK\d{16}`, "DK", 18},
	{`SE\d{22}`, "SE", 24},
	{`NO\d{13}`, "NO", 15},
	{`PL\d{26}`, "PL", 28},
	{`CZ\d{22}`, "CZ", 24},
	{`HU\d{26}`, "HU", 28},
	{`RO\d{2}[A-Z]{4}[A-Z0-9]{16}`, "RO", 24},
	{`BG\d{2}[A-Z]{4}\d{6}[A-Z0-9]{8}`, "BG", 22},
	{`HR\d{19}`, "HR", 21},
	{`SK\d{22}`, "SK", 24},
	{`SI\d{17}`, "SI", 19},
	{`LT\d{18}`, "LT", 20},
	{`LV\d{2}[A-Z]{4}[A-Z0-9]{13}`, "LV", 21},
	{`EE\d{18}`, "EE", 20},
	{`IS\d{24}`, "IS", 26},
	{`MT\d{2}[A-Z]{4}\d{5}[A-Z0-9]{18}`, "MT", 31},
	{`CY\d{26}`, "CY", 28},
	{`LI\d{19}`, "LI", 21},
	{`MC\d{25}`, "MC", 27},
	{`SM\d{2}[A-Z]\d{10}[A-Z0-9]{12}`, "SM", 27},
	{`AD\d{22}`, "AD", 24},
}

// ibanEntry holds a compiled country IBAN pattern.
type ibanEntry struct {
	re   *regexp.Regexp
	code string
}

// IBANRecognizer detects IBANs using country-specific regex + MOD-97 validation.
type IBANRecognizer struct {
	entries []ibanEntry
}

// NewIBANRecognizer creates a new IBAN recognizer.
func NewIBANRecognizer() *IBANRecognizer {
	entries := make([]ibanEntry, 0, len(ibanCountryPatterns))
	for _, p := range ibanCountryPatterns {
		entries = append(entries, ibanEntry{
			code: p.code,
			re:   regexp.MustCompile(p.regex),
		})
	}
	return &IBANRecognizer{entries: entries}
}

// Type returns IBAN.
func (r *IBANRecognizer) Type() EntityType {
	return IBAN
}

// Detect finds all IBANs in the given text.
func (r *IBANRecognizer) Detect(text string) []Entity {
	var entities []Entity

	for _, entry := range r.entries {
		matches := entry.re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			candidate := text[m[0]:m[1]]
			if validateIBAN(candidate) {
				entities = append(entities, Entity{
					Type:       IBAN,
					Value:      candidate,
					Confidence: 0.95,
					Source:     SourceMod97,
					Start:      m[0],
					End:        m[1],
				})
			}
		}
	}

	if len(entities) == 0 {
		return nil
	}
	return entities
}

// validateIBAN performs MOD-97-10 validation on an IBAN.
// Algorithm per ISO 7064:
//  1. Move the first 4 characters to the end
//  2. Convert letters to numbers (A=10, B=11, ..., Z=35)
//  3. Compute MOD 97 of the resulting large number
//  4. Result must be 1
func validateIBAN(iban string) bool {
	if len(iban) < 5 {
		return false
	}

	// Rearrange: first 4 chars to end.
	rearranged := iban[4:] + iban[:4]

	// Convert to numeric string.
	var numericStr strings.Builder
	numericStr.Grow(len(rearranged) * 2)
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		if c >= '0' && c <= '9' {
			numericStr.WriteByte(c)
		} else if c >= 'A' && c <= 'Z' {
			// Convert letter: A=10, B=11, ..., Z=35
			val := int(c - 'A' + 10)
			numericStr.WriteByte(byte('0' + val/10))
			numericStr.WriteByte(byte('0' + val%10))
		} else if c >= 'a' && c <= 'z' {
			val := int(c - 'a' + 10)
			numericStr.WriteByte(byte('0' + val/10))
			numericStr.WriteByte(byte('0' + val%10))
		} else {
			// Invalid character in IBAN.
			return false
		}
	}

	// MOD-97 of the large number using iterative division.
	return mod97(numericStr.String()) == 1
}

// mod97 computes the remainder when the numeric string is divided by 97.
// Uses iterative chunk processing to avoid overflow.
func mod97(num string) int {
	remainder := 0
	i := 0
	for i < len(num) {
		// Process up to 9 digits at a time (max safe for int32).
		chunkLen := 9
		if i+chunkLen > len(num) {
			chunkLen = len(num) - i
		}
		chunk := 0
		for j := 0; j < chunkLen; j++ {
			chunk = chunk*10 + int(num[i+j]-'0')
		}
		remainder = (remainder*intPow10(chunkLen) + chunk) % 97
		i += chunkLen
	}
	return remainder
}

// intPow10 returns 10^n for small n (n ≤ 9).
func intPow10(n int) int {
	p := 1
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}
