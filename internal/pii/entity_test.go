package pii

import (
	"strings"
	"testing"
)

func TestEntitySafeString(t *testing.T) {
	e := Entity{
		Type:       Email,
		Value:      "user@example.com",
		Confidence: 0.85,
		Source:     SourceRegex,
		Start:      10,
		End:        28,
	}

	safe := e.SafeString()
	// SafeString must never contain the actual PII value.
	if strings.Contains(safe, "user@example.com") {
		t.Error("SafeString() must not contain the entity Value")
	}
	if strings.Contains(safe, "user") {
		t.Error("SafeString() must not contain PII substrings")
	}
	if !strings.Contains(safe, "EMAIL") {
		t.Error("SafeString() must contain the type")
	}
	if !strings.Contains(safe, "0.85") {
		t.Error("SafeString() must contain the confidence")
	}
}

func TestEntityString(t *testing.T) {
	e := Entity{
		Type:       Phone,
		Value:      "+33 6 99 99 99 99",
		Confidence: 0.75,
		Source:     SourceRegex,
		Start:      0,
		End:        16,
	}

	str := e.String()
	// String() must also never contain the PII value.
	if strings.Contains(str, "33") {
		t.Error("String() must not contain PII")
	}
}

func TestEntityValueNeverLogged(t *testing.T) {
	// Simulate logging scenarios: ensure SafeString output is safe for all entity types.
	entities := []Entity{
		{Type: Email, Value: "test@example.com", Confidence: 0.90, Source: SourceRegex, Start: 0, End: 16},
		{Type: Phone, Value: "+1 202 555 0199", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 15},
		{Type: IBAN, Value: "DE89370400440532013000", Confidence: 0.95, Source: SourceMod97, Start: 0, End: 22},
		{Type: CreditCard, Value: "4111-1111-1111-1111", Confidence: 0.95, Source: SourceLuhn, Start: 0, End: 19},
		{Type: JWT, Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fakesig", Confidence: 0.80, Source: SourceStructural, Start: 0, End: 50},
		{Type: Name, Value: "Jean Dupont", Confidence: 0.70, Source: SourceEmailInference, Start: 0, End: 11},
		{Type: Secret, Value: "sk-test-deadbeefcafe", Confidence: 0.85, Source: SourcePrefix, Start: 0, End: 20},
		{Type: PrivateKey, Value: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhki...", Confidence: 0.90, Source: SourcePEMArmor, Start: 0, End: 50},
	}

	for _, e := range entities {
		s := e.SafeString()
		// Check no value leaks.
		if strings.Contains(s, e.Value) {
			t.Errorf("%s SafeString() leaked Value", e.Type)
		}
	}
}

func TestSourceKindConstants(t *testing.T) {
	// Ensure SourceKind constants have expected values.
	sources := map[SourceKind]bool{
		SourceRegex:          true,
		SourceLuhn:           true,
		SourceMod97:          true,
		SourceStructural:     true,
		SourceEmailInference: true,
		SourcePrefix:         true,
		SourceEntropy:        true,
		SourcePEMArmor:       true,
	}
	if len(sources) != 8 {
		t.Errorf("expected 8 source kinds, got %d", len(sources))
	}
}

func TestEntityTypeConstants(t *testing.T) {
	types := map[EntityType]bool{
		Email:      true,
		Phone:      true,
		IBAN:       true,
		CreditCard: true,
		JWT:        true,
		Name:       true,
		Secret:     true,
		PrivateKey: true,
	}
	if len(types) != 8 {
		t.Errorf("expected 8 entity types, got %d", len(types))
	}
}
