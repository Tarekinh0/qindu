package pii

import (
	"testing"
)

func TestPhoneRecognizerType(t *testing.T) {
	r := NewPhoneRecognizer()
	if r.Type() != Phone {
		t.Errorf("expected PHONE type, got %s", r.Type())
	}
}

func TestPhoneRecognizerFrench(t *testing.T) {
	r := NewPhoneRecognizer()
	tests := []struct {
		input string
		count int
	}{
		{"+33 6 99 99 99 99", 1},
		{"+33.6.99.99.99.99", 1},
		{"+33699999999", 1},
		{"06 99 99 99 99", 1},
		{"01 23 45 67 89", 1},
	}
	for _, tt := range tests {
		entities := r.Detect(tt.input)
		if len(entities) != tt.count {
			t.Errorf("expected %d phone in %q, got %d", tt.count, tt.input, len(entities))
		}
	}
}

func TestPhoneRecognizerUS(t *testing.T) {
	r := NewPhoneRecognizer()
	tests := []string{
		"+1 (202) 555-0199",
		"(202) 555-0199",
		"202-555-0199",
		"202.555.0199",
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) < 1 {
			t.Errorf("expected at least 1 phone in %q, got %d", input, len(entities))
		}
	}
}

func TestPhoneRecognizerInternational(t *testing.T) {
	r := NewPhoneRecognizer()
	tests := []string{
		"+44 20 7946 0958",
		"+49 30 12345678",
		"+39 06 12345678",
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) < 1 {
			t.Errorf("expected at least 1 phone in %q, got %d", input, len(entities))
		}
	}
}

func TestPhoneRecognizerInvalid(t *testing.T) {
	r := NewPhoneRecognizer()
	tests := []string{
		"",
		"not a phone",
		"12345",            // Too few digits.
		"1234567890123456", // Too many digits.
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 0 {
			t.Errorf("expected 0 entities for %q, got %d", input, len(entities))
		}
	}
}

func TestPhoneRecognizerAllSameDigit(t *testing.T) {
	r := NewPhoneRecognizer()
	// All same digit should get low confidence (below threshold, so filtered).
	entities := r.Detect("000-000-0000")
	// May or may not be detected depending on pattern match;
	// if detected, confidence should be low.
	for _, e := range entities {
		if e.Confidence >= 0.60 {
			t.Errorf("all-same-digit phone should have low confidence, got %f", e.Confidence)
		}
	}
}

func TestPhoneRecognizerSequential(t *testing.T) {
	r := NewPhoneRecognizer()
	// Sequential numbers should get downgraded confidence.
	entities := r.Detect("123-456-7890")
	for _, e := range entities {
		if e.Confidence >= 0.65 {
			t.Errorf("sequential phone should have low confidence, got %f", e.Confidence)
		}
	}
}

func TestPhoneRecognizerConfidence(t *testing.T) {
	r := NewPhoneRecognizer()
	entities := r.Detect("+33 6 99 99 99 99")
	if len(entities) < 1 {
		t.Fatal("expected at least 1 entity")
	}
	found := false
	for _, e := range entities {
		if e.Confidence > 0.80 {
			found = true
		}
	}
	if !found {
		t.Error("validated phone should have confidence >= 0.85")
	}
}

func TestPhoneRecognizerSpanValidation(t *testing.T) {
	r := NewPhoneRecognizer()
	text := "Call +33 6 99 99 99 99 today"
	entities := r.Detect(text)
	for _, e := range entities {
		if e.Start < 0 || e.End > len(text) || e.Start >= e.End {
			t.Errorf("invalid span: [%d, %d)", e.Start, e.End)
		}
		if text[e.Start:e.End] != e.Value {
			t.Errorf("Value mismatch: %q vs %q", text[e.Start:e.End], e.Value)
		}
	}
}

func TestExtractDigits(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"+33 6 99 99 99 99", "33699999999"},
		{"(202) 555-0199", "2025550199"},
		{"abc123def456", "123456"},
		{"", ""},
	}
	for _, tt := range tests {
		result := extractDigits(tt.input)
		if result != tt.expected {
			t.Errorf("extractDigits(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIsAllSameDigit(t *testing.T) {
	if !isAllSameDigit("00000") {
		t.Error("'00000' should be all same digit")
	}
	if !isAllSameDigit("1") {
		t.Error("'1' should be all same digit")
	}
	if isAllSameDigit("001") {
		t.Error("'001' should NOT be all same digit")
	}
	if isAllSameDigit("") {
		t.Error("empty should NOT be all same digit")
	}
}

func TestIsSequential(t *testing.T) {
	if !isSequential("123456") {
		t.Error("'123456' should be sequential")
	}
	if !isSequential("987654") {
		t.Error("'987654' should be sequential descending")
	}
	if isSequential("13579") {
		t.Error("'13579' should NOT be sequential")
	}
	if isSequential("12") {
		t.Error("'12' should NOT be sequential (< 3 chars)")
	}
}

func TestValidatePhoneNumberTooFewDigits(t *testing.T) {
	// Less than 7 digits should return 0.50.
	c := validatePhoneNumber("123")
	if c > 0.51 {
		t.Errorf("too few digits should have 0.50, got %f", c)
	}
}

func TestValidatePhoneNumberTooManyDigits(t *testing.T) {
	// More than 15 digits should return 0.50.
	c := validatePhoneNumber("1234567890123456")
	if c > 0.51 {
		t.Errorf("too many digits should have 0.50, got %f", c)
	}
}

func TestPhoneRecognizerConfidenceBelowThreshold(t *testing.T) {
	r := NewPhoneRecognizer()
	// A phone-like string with very few digits should be filtered out.
	entities := r.Detect("+1 23") // 3 digits only.
	if len(entities) != 0 {
		t.Errorf("too few digits should result in 0 entities, got %d", len(entities))
	}
}
