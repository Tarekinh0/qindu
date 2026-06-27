package pii

import (
	"testing"
)

func TestCreditCardRecognizerType(t *testing.T) {
	r := NewCreditCardRecognizer()
	if r.Type() != CreditCard {
		t.Errorf("expected CREDIT_CARD type, got %s", r.Type())
	}
}

func TestCreditCardRecognizerVisa(t *testing.T) {
	r := NewCreditCardRecognizer()
	tests := []string{
		"4111111111111111",    // Visa test number.
		"4111 1111 1111 1111", // With spaces.
		"4111-1111-1111-1111", // With dashes.
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 1 {
			t.Errorf("expected 1 Visa card in %q, got %d", input, len(entities))
		}
		if len(entities) > 0 && entities[0].Confidence != 0.95 {
			t.Errorf("valid Luhn card should have 0.95, got %f", entities[0].Confidence)
		}
	}
}

func TestCreditCardRecognizerMastercard(t *testing.T) {
	r := NewCreditCardRecognizer()
	tests := []string{
		"5555555555554444", // MC test number.
		"2223000048400011", // MC 2-series test.
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 1 {
			t.Errorf("expected 1 MC card in %q, got %d", input, len(entities))
		}
	}
}

func TestCreditCardRecognizerAmex(t *testing.T) {
	r := NewCreditCardRecognizer()
	entities := r.Detect("378282246310005") // Amex test number.
	if len(entities) != 1 {
		t.Errorf("expected 1 Amex card, got %d", len(entities))
	}
}

func TestCreditCardRecognizerDiscover(t *testing.T) {
	r := NewCreditCardRecognizer()
	entities := r.Detect("6011111111111117") // Discover test.
	if len(entities) != 1 {
		t.Errorf("expected 1 Discover card, got %d", len(entities))
	}
}

func TestCreditCardRecognizerInvalidLuhn(t *testing.T) {
	r := NewCreditCardRecognizer()
	// Valid BIN but fails Luhn.
	entities := r.Detect("4111111111111112") // Last digit wrong.
	if len(entities) != 0 {
		// Should still detect but with lower confidence.
		for _, e := range entities {
			if e.Confidence >= 0.95 {
				t.Errorf("invalid Luhn should not have 0.95 confidence")
			}
		}
	}
}

func TestCreditCardRecognizerInvalid(t *testing.T) {
	r := NewCreditCardRecognizer()
	tests := []string{
		"",
		"not a card",
		"12345",            // Too short.
		"9999999999999999", // Invalid prefix.
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 0 {
			t.Errorf("expected 0 entities for %q, got %d", input, len(entities))
		}
	}
}

func TestLuhnCheck(t *testing.T) {
	if !luhnCheck("4111111111111111") {
		t.Error("4111111111111111 should pass Luhn")
	}
	if luhnCheck("4111111111111112") {
		t.Error("4111111111111112 should fail Luhn")
	}
	if luhnCheck("5") {
		t.Error("single digit should fail Luhn")
	}
	if luhnCheck("") {
		t.Error("empty string should fail Luhn")
	}
}

func TestExtractDigitsCC(t *testing.T) {
	if extractDigitsCC("4111-1111-1111-1111") != "4111111111111111" {
		t.Error("extractDigitsCC failed on dashed format")
	}
}

func TestCreditCardRecognizerSpanValidation(t *testing.T) {
	r := NewCreditCardRecognizer()
	text := "Card: 4111111111111111 for payment"
	entities := r.Detect(text)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	e := entities[0]
	if e.Start < 6 || e.End > len(text) {
		t.Errorf("invalid span: [%d, %d)", e.Start, e.End)
	}
}

func TestMatchesAnyPrefixTooShort(t *testing.T) {
	// Digits shorter than any minLen should not match.
	if matchesAnyPrefix("4", creditCardPatterns) {
		t.Error("too short should not match any prefix")
	}
}

func TestMatchesAnyPrefixTooLong(t *testing.T) {
	// Digits longer than max allowed.
	long := "41111111111111111111" // 20 digits, max is 19.
	if matchesAnyPrefix(long, creditCardPatterns) {
		t.Error("20 digits should not match (max 19)")
	}
}

func TestMatchesAnyPrefixPrefixLongerThanDigits(t *testing.T) {
	// Create a pattern where a prefix is longer than the digits string.
	// The Visa pattern has prefix "4" (len 1), and minLen 13.
	// If we pass a 1-digit string "4", minLen is 13 so it's rejected first.
	// But the inner check `len(prefix) > len(digits)` is still reachable.
	// Use a custom pattern where prefix is long but minLen/maxLen pass.
	customPatterns := []ccPattern{
		{name: "Test", prefixes: []string{"12345"}, minLen: 3, maxLen: 20},
	}
	// digits "123" is shorter than prefix "12345", so the inner check triggers.
	if matchesAnyPrefix("123", customPatterns) {
		t.Error("prefix longer than digits should not match")
	}
}

func TestMatchesAnyPrefixDinersClub(t *testing.T) {
	// Diners Club 300-305 range, 14 digits.
	if !matchesAnyPrefix("30000000000000", creditCardPatterns) {
		t.Error("Diners Club 300 prefix should match")
	}
	if !matchesAnyPrefix("36000000000000", creditCardPatterns) {
		t.Error("Diners Club 36 prefix should match")
	}
}

func TestValidateCreditCardPrefixOnly(t *testing.T) {
	// Valid prefix but non-Luhn digits should get 0.85 confidence.
	// 4111111111111112 has Visa prefix but fails Luhn (changed last digit).
	result := validateCreditCard("4111111111111112")
	if result.confidence != 0.85 {
		t.Errorf("valid BIN + invalid Luhn should have 0.85 confidence, got %f", result.confidence)
	}
}

func TestValidateCreditCardNoPrefix(t *testing.T) {
	// Valid Luhn but no matching BIN prefix.
	result := validateCreditCard("0000000000000000") // All zeros, passes Luhn but no prefix.
	if result.confidence != 0 {
		t.Errorf("no matching prefix should have 0 confidence, got %f", result.confidence)
	}
}
