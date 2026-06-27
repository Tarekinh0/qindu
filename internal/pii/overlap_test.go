package pii

import (
	"reflect"
	"testing"
)

func TestResolveOverlapsEmpty(t *testing.T) {
	result := resolveOverlaps(nil)
	if result != nil {
		t.Error("resolveOverlaps of nil should return nil")
	}
	result = resolveOverlaps([]Entity{})
	if len(result) != 0 {
		t.Error("resolveOverlaps of empty slice should return empty")
	}
}

func TestResolveOverlapsSingleEntity(t *testing.T) {
	entities := []Entity{
		{Type: Email, Value: "test@example.com", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 16},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(result))
	}
	if result[0].Start != 0 || result[0].End != 16 {
		t.Error("entity positions changed")
	}
}

func TestResolveOverlapsNoOverlap(t *testing.T) {
	entities := []Entity{
		{Type: Email, Value: "a@b.com", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 7},
		{Type: Phone, Value: "12345678", Confidence: 0.75, Source: SourceRegex, Start: 10, End: 18},
	}
	result := resolveOverlaps(entities)
	if len(result) != 2 {
		t.Fatalf("expected 2 non-overlapping entities, got %d", len(result))
	}
}

func TestResolveOverlapsAdjacent(t *testing.T) {
	// Adjacent entities (End_A == Start_B) are NOT overlapping.
	entities := []Entity{
		{Type: Email, Value: "a@b.com", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 7},
		{Type: JWT, Value: "a.b.c", Confidence: 0.80, Source: SourceStructural, Start: 7, End: 12},
	}
	result := resolveOverlaps(entities)
	if len(result) != 2 {
		t.Fatalf("adjacent entities should both survive, got %d", len(result))
	}
}

func TestResolveOverlapsHigherConfidenceWins(t *testing.T) {
	entities := []Entity{
		{Type: Email, Value: "test@ex.com", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 10},
		{Type: Secret, Value: "test@ex.co", Confidence: 0.95, Source: SourceEntropy, Start: 0, End: 11},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	if result[0].Confidence != 0.95 {
		t.Error("higher confidence entity should win")
	}
}

func TestResolveOverlapsTypePriority(t *testing.T) {
	// Same confidence, different types. EMAIL should have higher priority.
	entities := []Entity{
		{Type: Secret, Value: "sk-test123", Confidence: 0.85, Source: SourcePrefix, Start: 0, End: 10},
		{Type: Email, Value: "a@b.com", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 7},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	// EMAIL has higher priority than SECRET.
	if result[0].Type != Email {
		t.Errorf("EMAIL should have priority over SECRET, got %s", result[0].Type)
	}
}

func TestResolveOverlapsLongerSpanWins(t *testing.T) {
	// Same type, same confidence, different lengths.
	entities := []Entity{
		{Type: Secret, Value: "ab", Confidence: 0.85, Source: SourceEntropy, Start: 0, End: 2},
		{Type: Secret, Value: "abcd", Confidence: 0.85, Source: SourceEntropy, Start: 0, End: 4},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	if result[0].End-result[0].Start != 4 {
		t.Error("longer span should win")
	}
}

func TestResolveOverlapsMultipleOverlaps(t *testing.T) {
	// Complex scenario with multiple overlapping entities.
	entities := []Entity{
		{Type: Email, Value: "test@ex.com", Confidence: 0.90, Source: SourceRegex, Start: 0, End: 11},
		{Type: Phone, Value: "555-1234", Confidence: 0.85, Source: SourceRegex, Start: 5, End: 13},
		{Type: JWT, Value: "a.b.c", Confidence: 0.80, Source: SourceStructural, Start: 15, End: 20},
		{Type: Secret, Value: "secret123", Confidence: 0.70, Source: SourceEntropy, Start: 15, End: 24},
	}
	result := resolveOverlaps(entities)
	// First overlap (0-11 vs 5-13): EMAIL 0.90 > PHONE 0.85, EMAIL wins.
	// Second overlap (15-20 vs 15-24): JWT 0.80 > SECRET 0.70, JWT wins.
	if len(result) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(result))
	}
	// Verify both results.
	var emailFound, jwtFound bool
	for _, e := range result {
		if e.Type == Email && e.End == 11 {
			emailFound = true
		}
		if e.Type == JWT && e.End == 20 {
			jwtFound = true
		}
	}
	if !emailFound {
		t.Error("EMAIL entity should survive")
	}
	if !jwtFound {
		t.Error("JWT entity should survive")
	}
}

func TestResolveOverlapsSameEverything(t *testing.T) {
	// Same type, same confidence, same length.
	entities := []Entity{
		{Type: Secret, Value: "abcdef", Confidence: 0.85, Source: SourceEntropy, Start: 0, End: 6},
		{Type: Secret, Value: "ghijkl", Confidence: 0.85, Source: SourceEntropy, Start: 0, End: 6},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
}

func TestResolveOverlapsSplitLevel(t *testing.T) {
	// Two overlapping entities with the same confidence and same type.
	// The later entity has a bigger span, so it should win.
	entities := []Entity{
		{Type: Name, Value: "John", Confidence: 0.40, Source: SourceEmailInference, Start: 0, End: 4},
		{Type: Name, Value: "John Doe", Confidence: 0.40, Source: SourceEmailInference, Start: 0, End: 8},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	if result[0].End != 8 {
		t.Error("larger span should win")
	}
}

func TestEntityTypePriorityOrder(t *testing.T) {
	// Verify the priority ordering.
	expected := []EntityType{Email, Phone, IBAN, CreditCard, JWT, Name, Secret, PrivateKey}
	for i, et := range expected {
		if entityTypePriorityOrder(et) != i {
			t.Errorf("priority of %s should be %d, got %d", et, i, entityTypePriorityOrder(et))
		}
	}
	// Unknown type gets lowest priority.
	if entityTypePriorityOrder("UNKNOWN") != 999 {
		t.Error("unknown type should have priority 999")
	}
}

func TestResolveOverlapsMaintainsOrder(t *testing.T) {
	// Non-overlapping entities should maintain their registration order.
	entities := []Entity{
		{Type: Email, Value: "a@b.com", Confidence: 0.85, Source: SourceRegex, Start: 50, End: 57},
		{Type: Phone, Value: "123", Confidence: 0.75, Source: SourceRegex, Start: 0, End: 3},
		{Type: JWT, Value: "x.y.z", Confidence: 0.80, Source: SourceStructural, Start: 25, End: 30},
	}
	result := resolveOverlaps(entities)
	if len(result) != 3 {
		t.Fatalf("expected 3 entities, got %d", len(result))
	}
	// After sorting, should be ordered by Start position.
	if result[0].Start != 0 || result[1].Start != 25 || result[2].Start != 50 {
		t.Errorf("entities not sorted by position: %v", result)
	}
}

func TestResolveOverlapsDeterminism(t *testing.T) {
	// Run overlap resolution 100 times on the same input to verify determinism.
	input := []Entity{
		{Type: Email, Value: "a@b.com", Confidence: 0.85, Source: SourceRegex, Start: 0, End: 7},
		{Type: Secret, Value: "a@b.c", Confidence: 0.85, Source: SourceEntropy, Start: 0, End: 5},
		{Type: JWT, Value: "x.y.z", Confidence: 0.80, Source: SourceStructural, Start: 10, End: 15},
	}

	var firstResult []Entity
	for i := 0; i < 100; i++ {
		// Make a copy for each iteration.
		testInput := make([]Entity, len(input))
		copy(testInput, input)
		result := resolveOverlaps(testInput)
		if i == 0 {
			firstResult = result
		} else {
			if !reflect.DeepEqual(firstResult, result) {
				t.Fatalf("resolveOverlaps is not deterministic at iteration %d", i)
			}
		}
	}
}

func TestPickWinnerHigherConfidenceB(t *testing.T) {
	// B has higher confidence, should win.
	a := Entity{Type: Email, Confidence: 0.70, Start: 0, End: 10}
	b := Entity{Type: Secret, Confidence: 0.90, Start: 0, End: 8}
	winner := pickWinner(a, b)
	if winner.Confidence != 0.90 {
		t.Error("B with higher confidence should win")
	}
}

func TestPickWinnerTypePriorityBHigher(t *testing.T) {
	// Same confidence, B has higher type priority.
	a := Entity{Type: Secret, Confidence: 0.85, Start: 0, End: 10}
	b := Entity{Type: Email, Confidence: 0.85, Start: 0, End: 10}
	winner := pickWinner(a, b)
	if winner.Type != Email {
		t.Error("EMAIL should have priority over SECRET")
	}
}

func TestPickWinnerLongerSpanB(t *testing.T) {
	// Same type, same confidence, B has longer span.
	a := Entity{Type: Secret, Confidence: 0.85, Start: 0, End: 5}
	b := Entity{Type: Secret, Confidence: 0.85, Start: 0, End: 10}
	winner := pickWinner(a, b)
	if (winner.End - winner.Start) != 10 {
		t.Error("longer span should win")
	}
}

func TestPickWinnerSameAll(t *testing.T) {
	// All tiebreakers exhausted — first (a) wins.
	a := Entity{Type: Secret, Confidence: 0.85, Start: 0, End: 10}
	b := Entity{Type: Secret, Confidence: 0.85, Start: 0, End: 10}
	winner := pickWinner(a, b)
	if (winner.End - winner.Start) != 10 {
		t.Error("should return a when all else equal")
	}
}

func TestResolveOverlapsNewEntityWins(t *testing.T) {
	// New entity has higher confidence and replaces the kept one.
	entities := []Entity{
		{Type: Email, Value: "test@ex.com", Confidence: 0.60, Source: SourceRegex, Start: 0, End: 10},
		{Type: Secret, Value: "test@ex.co", Confidence: 0.95, Source: SourceEntropy, Start: 0, End: 11},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	if result[0].Confidence != 0.95 {
		t.Error("higher confidence should win")
	}
}
