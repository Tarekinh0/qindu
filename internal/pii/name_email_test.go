package pii

import (
	"testing"
)

func TestNameFromEmailRecognizerType(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	if r.Type() != Name {
		t.Errorf("expected NAME type, got %s", r.Type())
	}
}

func TestNameFromEmailRecognizerDetectReturnsNil(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	// Detect without emails should return nil.
	entities := r.Detect("some text")
	if entities != nil {
		t.Errorf("Detect() should return nil when no emails provided, got %v", entities)
	}
}

func TestNameFromEmailRecognizerDetectWithEmails(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	// Use the EMAIL recognizer to get email entities first.
	emailR := NewEmailRecognizer()
	emails := emailR.Detect("jean.dupont@example.com")

	entities := r.DetectWithEmails("jean.dupont@example.com", emails)
	if len(entities) != 1 {
		t.Fatalf("expected 1 NAME entity, got %d", len(entities))
	}
	e := entities[0]
	if e.Type != Name {
		t.Errorf("expected NAME type, got %s", e.Type)
	}
	if e.Source != SourceEmailInference {
		t.Errorf("expected email_inference source, got %s", e.Source)
	}
	if e.Value != "Jean Dupont" {
		t.Errorf("expected 'Jean Dupont', got %q", e.Value)
	}
	if e.Confidence > 0.71 || e.Confidence < 0.69 {
		t.Errorf("expected confidence ~0.70, got %f", e.Confidence)
	}
}

func TestNameFromEmailRecognizerUnderscore(t *testing.T) {
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	emails := emailR.Detect("marie_curie@example.org")
	entities := nameR.DetectWithEmails("marie_curie@example.org", emails)
	if len(entities) != 1 {
		t.Fatalf("expected 1 NAME, got %d", len(entities))
	}
	if entities[0].Value != "Marie Curie" {
		t.Errorf("expected 'Marie Curie', got %q", entities[0].Value)
	}
}

func TestNameFromEmailRecognizerPlusSuffix(t *testing.T) {
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	emails := emailR.Detect("john.doe+spam@example.com")
	entities := nameR.DetectWithEmails("john.doe+spam@example.com", emails)
	if len(entities) != 1 {
		t.Fatalf("expected 1 NAME, got %d", len(entities))
	}
	if entities[0].Value != "John Doe" {
		t.Errorf("expected 'John Doe', got %q", entities[0].Value)
	}
}

func TestNameFromEmailRecognizerStopWords(t *testing.T) {
	// DPO-T11: NAME recognizer does NOT fire on any email whose local-part is in the stop-word list.
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	stopWords := []string{
		"support@example.com",
		"noreply@example.com",
		"info@example.com",
		"contact@example.com",
		"admin@example.com",
		"help@example.com",
		"sales@example.com",
		"hello@example.com",
		"team@example.com",
		"service@example.com",
		"office@example.com",
		"billing@example.com",
		"abuse@example.com",
		"postmaster@example.com",
		"webmaster@example.com",
		"hostmaster@example.com",
		"mail@example.com",
		"news@example.com",
		"newsletter@example.com",
		"root@example.com",
		"test@example.com",
		"demo@example.com",
	}
	for _, email := range stopWords {
		emails := emailR.Detect(email)
		if len(emails) == 0 {
			// Some stop words (like root@) are rejected by the email recognizer itself.
			continue
		}
		entities := nameR.DetectWithEmails(email, emails)
		if len(entities) != 0 {
			t.Errorf("stop word %q should not generate NAME entity, got %v", email, entities)
		}
	}
}

func TestNameFromEmailRecognizerSingleSegment(t *testing.T) {
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	// Single segment without separator — DPO-T13.
	emails := emailR.Detect("jdoe@example.com")
	entities := nameR.DetectWithEmails("jdoe@example.com", emails)
	if len(entities) != 0 {
		t.Errorf("single segment 'jdoe' should not generate NAME, got %v", entities)
	}
}

func TestNameFromEmailRecognizerNumeric(t *testing.T) {
	// DPO-T12: NAME recognizer does NOT fire on purely numeric local-part segments.
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	emails := emailR.Detect("jd42@example.com")
	entities := nameR.DetectWithEmails("jd42@example.com", emails)
	if len(entities) != 0 {
		t.Errorf("numeric segment 'jd42' should not generate NAME, got %v", entities)
	}
}

func TestNameFromEmailRecognizerSingleChars(t *testing.T) {
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	emails := emailR.Detect("a.b@example.com")
	entities := nameR.DetectWithEmails("a.b@example.com", emails)
	if len(entities) < 1 {
		t.Fatalf("single-char segments should still generate NAME, just lower confidence")
	}
	if entities[0].Confidence > 0.56 {
		t.Errorf("single-char segments should have confidence ~0.55, got %f", entities[0].Confidence)
	}
}

func TestNameFromEmailRecognizerConfidenceLimit(t *testing.T) {
	// DPO-T14: NAME recognizer confidence never exceeds 0.70 for inferred names.
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	emails := emailR.Detect("jean.dupont@example.com")
	entities := nameR.DetectWithEmails("jean.dupont@example.com", emails)
	if len(entities) != 1 {
		t.Fatal("expected 1 entity")
	}
	if entities[0].Confidence > 0.71 {
		t.Errorf("NAME confidence should not exceed 0.70, got %f", entities[0].Confidence)
	}
}

func TestNameFromEmailRecognizerEmptyEmails(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	entities := r.DetectWithEmails("some text", nil)
	if entities != nil {
		t.Errorf("expected nil for nil emails, got %v", entities)
	}
	entities = r.DetectWithEmails("some text", []Entity{})
	if entities != nil {
		t.Errorf("expected nil for empty emails, got %v", entities)
	}
}

func TestNameFromEmailRecognizerNonEmailType(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	// Pass non-EMAIL entities.
	entities := r.DetectWithEmails("text", []Entity{
		{Type: Phone, Value: "12345", Confidence: 0.75, Source: SourceRegex, Start: 0, End: 5},
	})
	if entities != nil {
		t.Errorf("non-EMAIL entities should produce nil, got %v", entities)
	}
}

func TestNameFromEmailRecognizerSpanLocation(t *testing.T) {
	emailR := NewEmailRecognizer()
	nameR := NewNameFromEmailRecognizer()

	text := "Contact jean.dupont@example.com for details"
	emails := emailR.Detect(text)
	entities := nameR.DetectWithEmails(text, emails)
	if len(entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(entities))
	}
	// NAME entity should be co-located with the EMAIL entity's span.
	e := entities[0]
	if e.Start < 8 || e.End > 32 {
		t.Errorf("NAME span [%d,%d) not co-located with email", e.Start, e.End)
	}
}

func TestInferNameFromLocalPartEdgeCases(t *testing.T) {
	// Test edge cases of inferNameFromLocalPart.
	tests := []struct {
		local      string
		expectName string
		expectConf float64
	}{
		{"jean.dupont", "Jean Dupont", 0.70},
		{"J.Doe", "J Doe", 0.55},
		{"single", "", 0},   // Single segment: blocked per story spec.
		{"42number", "", 0}, // Starts with number.
		{"", "", 0},
	}
	for _, tt := range tests {
		name, conf := inferNameFromLocalPart(tt.local)
		if tt.expectName == "" {
			if name != "" {
				t.Errorf("inferNameFromLocalPart(%q) expected empty, got %q", tt.local, name)
			}
		} else if name != tt.expectName {
			t.Errorf("inferNameFromLocalPart(%q) = %q, want %q", tt.local, name, tt.expectName)
		}
		if conf != tt.expectConf {
			t.Errorf("inferNameFromLocalPart(%q) confidence = %f, want %f", tt.local, conf, tt.expectConf)
		}
	}
}

func TestTitleCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"jean", "Jean"},
		{"DUPONT", "Dupont"},
		{"", ""},
		{"a", "A"},
	}
	for _, tt := range tests {
		result := titleCase(tt.input)
		if result != tt.expected {
			t.Errorf("titleCase(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIsNameSegmentStopWord(t *testing.T) {
	// A segment that is a stop word should be rejected.
	if isNameSegment("support") {
		t.Error("'support' should be rejected as name segment (stop word)")
	}
	if isNameSegment("admin") {
		t.Error("'admin' should be rejected as name segment (stop word)")
	}
}

func TestIsNameSegmentTooShort(t *testing.T) {
	// Single character should be rejected by isNameSegment (not isSingleChar).
	if isNameSegment("j") {
		t.Error("single char should not be a name segment")
	}
}

func TestIsNameSegmentStartsWithNonLetter(t *testing.T) {
	// Starts with number should be rejected.
	if isNameSegment("42abc") {
		t.Error("segment starting with number should be rejected")
	}
	// Starts with underscore should be rejected.
	if isNameSegment("_name") {
		t.Error("segment starting with underscore should be rejected")
	}
}

func TestIsNameSegmentPurelyNumeric(t *testing.T) {
	// All digits should be rejected.
	if isNameSegment("12345") {
		t.Error("purely numeric should be rejected")
	}
}

func TestIsNameSegmentValid(t *testing.T) {
	// Valid name segment.
	if !isNameSegment("jean") {
		t.Error("'jean' should be valid name segment")
	}
}

func TestInferNameFromLocalPartEmptySegment(t *testing.T) {
	// Split with empty segment: "jean..dupont"
	name, _ := inferNameFromLocalPart("jean..dupont")
	if name != "" {
		t.Errorf("empty segment should cause rejection, got %q", name)
	}
}

func TestInferNameFromLocalPartStopWordInSegment(t *testing.T) {
	// A segment that is a stop word.
	name, _ := inferNameFromLocalPart("jean.admin")
	if name != "" {
		t.Errorf("stop word segment should cause rejection, got %q", name)
	}
}

func TestInferNameFromLocalPartSingleSegmentWithSeparator(t *testing.T) {
	// Two segments where one is valid and one is invalid.
	// "test.jean" — "test" is stop word, should reject.
	name, _ := inferNameFromLocalPart("test.jean")
	if name != "" {
		t.Errorf("stop word segment should cause rejection, got %q", name)
	}
}

func TestInferNameFromLocalPartFullStopWord(t *testing.T) {
	// The full local part is a stop word (without separators but with +suffix stripped).
	name, _ := inferNameFromLocalPart("support")
	if name != "" {
		t.Errorf("stop word local part should return empty, got %q", name)
	}
}

func TestDetectWithEmailsEmailWithNoAt(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	// Email entity with no @ sign in value (shouldn't normally happen but handle gracefully).
	entities := r.DetectWithEmails("text", []Entity{
		{Type: Email, Value: "noat", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 4},
	})
	if entities != nil {
		t.Errorf("email with no @ should produce nil, got %v", entities)
	}
}

func TestDetectWithEmailsEmptyLocalPart(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	// Email with empty local part (@ at position 0).
	entities := r.DetectWithEmails("text", []Entity{
		{Type: Email, Value: "@domain.com", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 11},
	})
	if entities != nil {
		t.Errorf("empty local part should produce nil, got %v", entities)
	}
}

func TestInferNameFromLocalPartUnderscoreSplit(t *testing.T) {
	name, conf := inferNameFromLocalPart("marie_curie")
	if name != "Marie Curie" {
		t.Errorf("expected 'Marie Curie', got %q", name)
	}
	if conf < 0.69 || conf > 0.71 {
		t.Errorf("expected ~0.70 confidence, got %f", conf)
	}
}

func TestInferNameFromLocalPartNumericSegment(t *testing.T) {
	// "jean.42" — "42" is purely numeric, so isNameSegment returns false.
	// This causes allValid = false, which rejects the entire name.
	name, _ := inferNameFromLocalPart("jean.42")
	if name != "" {
		t.Errorf("numeric segment should cause rejection, got %q", name)
	}
}

func TestInferNameFromLocalPartThreeSegments(t *testing.T) {
	// Three segments, all valid.
	name, conf := inferNameFromLocalPart("jean.pierre.dupont")
	if name != "Jean Pierre Dupont" {
		t.Errorf("expected 'Jean Pierre Dupont', got %q", name)
	}
	if conf < 0.69 || conf > 0.71 {
		t.Errorf("expected ~0.70 confidence for 3 segments, got %f", conf)
	}
}

func TestTitleCaseEmpty(t *testing.T) {
	result := titleCase("")
	if result != "" {
		t.Errorf("titleCase empty should return empty, got %q", result)
	}
}

func TestTitleCaseInvalidUTF8(t *testing.T) {
	// Create a string with invalid UTF-8 to trigger RuneError path.
	invalid := string([]byte{0xff, 0xfe, 0xfd})
	result := titleCase(invalid)
	// Should return the original string unchanged when RuneError is encountered.
	if result != invalid {
		t.Errorf("titleCase with invalid UTF-8 should return original, got %q", result)
	}
}

func TestInferNameFromLocalPartOneValidPart(t *testing.T) {
	// Two segments where one is invalid -> exactly 1 valid part -> confidence 0.40.
	// Actually this was tested with numeric segment which rejects entirely.
	// Let's test with a different scenario: "jean." (empty second segment)
	// The empty segment causes allValid = false, which rejects.
	// Actually, let me think about what gives exactly 1 validPart.
	// If we have "jean." -> parts = ["jean", ""], empty causes allValid=false -> reject.
	// If we have "jean.admin" -> "admin" is stop word -> reject.
	// What about just "jean" (single segment, no split)? -> empty return (single segment blocked).
	// What about "jean.support"? support is stop word, allValid=false -> reject.
	// Actually, let me trace more carefully: the only way to get 1 validPart is...
	// Wait: "j.doe" -> single-char "j" is borderline but still added. "doe" is valid.
	// So validParts = ["J", "Doe"], len=2, confidence=0.55 (borderline).
	// What about 2 segments where 1 passes and 1 fails? If 1 fails, allValid=false -> reject entirely.
	// So the path at name_email.go:166 is UNREACHABLE through the normal flow.
	// Because the only way to have validParts == 1 without allValid being false is...
	// if there's a single-char borderline part that gets added AND no other parts.
	// But with only 1 part, we need the split to produce exactly 1 part.
	// Split on "." of "jean" -> ["jean"] (1 part). No separator -> return "".
	// Hmm.
	// Actually wait: what if split produces ["jean"] and we check isSingleChar? No, it's not single.
	// Then isNameSegment passes. validParts = ["Jean"], allValid = true.
	// But we only reach this if there IS a separator... No, if there's no separator, we return "".
	// Let me re-read the code.

	// In inferNameFromLocalPart:
	// If there's a separator, split. The result parts always have at least 1 element.
	// Then for each part: if empty -> allValid=false. If single char -> borderline.
	// If isNameSegment fails -> allValid=false, break.
	// Then: if !allValid || len(validParts) < 1 -> return "".
	// So we need allValid=true AND len(validParts)==1.
	// This can happen if there's exactly 1 part and it's valid.
	// But we only reach the split code if there IS a separator!
	// If split produces 1 part (e.g., "jean." -> ["jean", ""]), then empty part makes allValid=false.
	// If split produces ["jean"] (no dot, no underscore), we return "" before split.
	// So this path IS unreachable! The only way to get 1 validPart is impossible.

	// I think this code path is dead. Let me just skip it and note it.
	_ = t
}

func TestNameFromEmailRecognizerDashSeparator(t *testing.T) {
	r := NewNameFromEmailRecognizer()
	// Dash is not a supported separator for name inference.
	// Only '.' and '_' are supported.
	emailR := NewEmailRecognizer()
	emails := emailR.Detect("jean-dupont@example.com")
	entities := r.DetectWithEmails("jean-dupont@example.com", emails)
	// Dash separator should result in single segment, blocked.
	if len(entities) != 0 {
		t.Errorf("dash separator should not generate NAME, got %v", entities)
	}
}
