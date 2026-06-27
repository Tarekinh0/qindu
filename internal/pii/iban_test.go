package pii

import (
	"testing"
)

func TestIBANRecognizerType(t *testing.T) {
	r := NewIBANRecognizer()
	if r.Type() != IBAN {
		t.Errorf("expected IBAN type, got %s", r.Type())
	}
}

func TestIBANRecognizerValid(t *testing.T) {
	r := NewIBANRecognizer()
	// Use test IBANs from official sources.
	tests := []string{
		"DE89370400440532013000",      // DE test
		"FR1420041010050500013M02606", // FR test
		"GB29NWBK60161331926819",      // GB test
		"ES9121000418450200051332",    // ES test
		"IT60X0542811101000000123456", // IT test
	}
	for _, iban := range tests {
		entities := r.Detect(iban)
		if len(entities) != 1 {
			t.Errorf("expected 1 IBAN for %q, got %d", iban, len(entities))
		}
		if len(entities) > 0 {
			if entities[0].Confidence != 0.95 {
				t.Errorf("valid IBAN should have 0.95 confidence, got %f", entities[0].Confidence)
			}
			if entities[0].Source != SourceMod97 {
				t.Errorf("expected mod97 source, got %s", entities[0].Source)
			}
		}
	}
}

func TestIBANRecognizerInvalidChecksum(t *testing.T) {
	r := NewIBANRecognizer()
	// Modified check digits should fail MOD-97.
	// DE89370400440532013000 is valid. Change a digit.
	badIBANs := []string{
		"DE99370400440532013001", // Modified.
		"DE00370400440532013000", // Wrong check digits.
	}
	for _, iban := range badIBANs {
		entities := r.Detect(iban)
		if len(entities) != 0 {
			t.Errorf("invalid IBAN %q should be rejected, got %v", iban, entities)
		}
	}
}

func TestIBANRecognizerInvalid(t *testing.T) {
	r := NewIBANRecognizer()
	tests := []string{
		"",
		"not an iban",
		"DE123",                  // Too short.
		"ZZ89370400440532013000", // Unknown country.
	}
	for _, input := range tests {
		entities := r.Detect(input)
		if len(entities) != 0 {
			t.Errorf("expected 0 entities for %q, got %d", input, len(entities))
		}
	}
}

func TestIBANRecognizerSpanValidation(t *testing.T) {
	r := NewIBANRecognizer()
	text := "IBAN: DE89370400440532013000 for payment"
	entities := r.Detect(text)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	e := entities[0]
	if e.Start < 6 || e.End > len(text) {
		t.Errorf("invalid span: [%d, %d)", e.Start, e.End)
	}
	if text[e.Start:e.End] != e.Value {
		t.Errorf("value mismatch: text[%d:%d]=%q != Value=%q", e.Start, e.End, text[e.Start:e.End], e.Value)
	}
}

func TestMod97(t *testing.T) {
	if mod97("1") != 1 {
		t.Error("mod97(1) should be 1")
	}
	if mod97("0") != 0 {
		t.Error("mod97(0) should be 0")
	}
}

func TestValidateIBANEdgeCases(t *testing.T) {
	if validateIBAN("") {
		t.Error("empty IBAN should be invalid")
	}
	if validateIBAN("DE") {
		t.Error("too short IBAN should be invalid")
	}
	// Lowercase letters.
	if !validateIBAN("de89370400440532013000") {
		t.Error("lowercase IBAN with valid checksum should be valid")
	}
	// Invalid characters in IBAN.
	if validateIBAN("DE89-70400440532013000") {
		t.Error("IBAN with hyphen should be invalid")
	}
	// Non-alphanumeric char.
	if validateIBAN("DE89!70400440532013000") {
		t.Error("IBAN with special char should be invalid")
	}
}
