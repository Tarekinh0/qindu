package tokenize

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Tarekinh0/qindu/internal/pii"
)

// buildTokenPattern returns a strict regex for matching <<TYPE_N>> tokens,
// where TYPE is one of the known entity types and N is a decimal integer.
// This is compiled once at package init and reused across all rehydration calls.
func buildTokenPattern() *regexp.Regexp {
	var parts []string
	for _, t := range allEntityTypes {
		parts = append(parts, regexp.QuoteMeta(string(t)))
	}
	// Pattern: <<(TYPE1|TYPE2|...)_\d+>>
	pattern := `<<(` + strings.Join(parts, "|") + `)_(\d+)>>`
	return regexp.MustCompile(pattern)
}

// tokenRegex matches <<TYPE_N>> patterns for rehydration.
// Compiled once at package init. Linear-time, no backtracking vulnerabilities.
var tokenRegex = buildTokenPattern()

// allEntityTypes is the canonical list of recognized PII entity types.
// Both buildTokenPattern and isKnownEntityType reference this single list,
// ensuring DRY and OCP compliance.
var allEntityTypes = []pii.EntityType{
	pii.Email, pii.Phone, pii.IBAN, pii.CreditCard,
	pii.JWT, pii.Name, pii.Secret, pii.PrivateKey,
}

// knownEntityTypes is a set of recognized entity types for O(1) lookup.
var knownEntityTypes = func() map[pii.EntityType]bool {
	m := make(map[pii.EntityType]bool, len(allEntityTypes))
	for _, et := range allEntityTypes {
		m[et] = true
	}
	return m
}()

// formatToken builds a <<TYPE_N>> token string.
// Uses only the entity type and counter — never the PII value (SR-2).
func formatToken(entityType pii.EntityType, counter uint64) string {
	return fmt.Sprintf("<<%s_%d>>", entityType, counter)
}

// Tokenizer replaces detected PII entities with opaque placeholder tokens
// and can restore original values during rehydration.
//
// Each Tokenizer instance represents a single conversation scope.
// Tokens and counters are independent between instances.
// Safe for concurrent use.
type Tokenizer struct {
	engine   *pii.Engine
	store    Store
	counters map[pii.EntityType]uint64
	// valueToToken maps PII values to their assigned tokens for deduplication.
	// WARNING: map keys contain raw PII. Never log, serialize, or print this field.
	valueToToken map[string]string
	logger       *slog.Logger
	mu           sync.Mutex // protects counters and valueToToken
}

// Option configures a Tokenizer.
type Option func(*Tokenizer)

// WithStore sets a custom Store implementation (injectable for future vault).
// If nil, a default MemoryStore is created with memory locking.
func WithStore(store Store) Option {
	return func(t *Tokenizer) {
		if store != nil {
			t.store = store
		}
	}
}

// WithLogger sets the structured logger for the tokenizer.
func WithLogger(logger *slog.Logger) Option {
	return func(t *Tokenizer) {
		if logger != nil {
			t.logger = logger
		}
	}
}

// New creates a new Tokenizer with the given PII detection engine.
// Each call to New creates an independent conversation scope with fresh counters.
func New(engine *pii.Engine, opts ...Option) *Tokenizer {
	t := &Tokenizer{
		engine:       engine,
		counters:     make(map[pii.EntityType]uint64),
		valueToToken: make(map[string]string),
	}
	for _, opt := range opts {
		opt(t)
	}
	if t.logger == nil {
		t.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if t.store == nil {
		t.store = NewMemoryStore(t.logger)
	}
	return t
}

// Tokenize replaces all detected PII entities in text with <<TYPE_N>> tokens.
//
// The input is first passed through the PII detection engine. Detected entities
// are replaced using the original byte offsets. Since the source string is
// immutable in Go, left-to-right replacement with a strings.Builder is
// equivalent to right-to-left on a mutable buffer.
//
// PII values are stored in the in-memory mapping for later rehydration.
//
// Returns the tokenized text (with zero raw PII) or an error.
func (t *Tokenizer) Tokenize(text string) (string, error) {
	// Empty input fast path.
	if len(strings.TrimSpace(text)) == 0 {
		return text, nil
	}

	// Run PII detection (Engine handles input size bounds).
	entities, err := t.engine.Detect(text)
	if err != nil {
		return "", err // Engine returns PII-free errors
	}

	// No PII detected — return text unchanged.
	if len(entities) == 0 {
		return text, nil
	}

	// Validate entities for defense-in-depth.
	entities = validateEntities(entities, len(text))
	if len(entities) == 0 {
		return text, nil
	}

	// Assign tokens to each entity (deduplicate by value within this conversation).
	entityTokens := t.assignTokens(entities)

	// Replace PII spans with tokens.
	return substituteEntities(text, entities, entityTokens), nil
}

// assignTokens maps each entity to a token, reusing tokens for duplicate PII values.
// Must be safe for concurrent use.
func (t *Tokenizer) assignTokens(entities []pii.Entity) []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	tokens := make([]string, len(entities))
	for i := range entities {
		e := &entities[i]
		// Check if this PII value was already tokenized in this conversation.
		if existingToken, ok := t.valueToToken[e.Value]; ok {
			tokens[i] = existingToken
			continue
		}
		// New PII value — increment counter and create token.
		t.counters[e.Type]++
		counter := t.counters[e.Type]
		token := formatToken(e.Type, counter)
		tokens[i] = token
		// Store both directions.
		t.valueToToken[e.Value] = token
		t.store.Map(token, e.Value)
	}
	return tokens
}

// Rehydrate restores <<TYPE_N>> tokens back to their original PII values.
//
// Tokens not found in the mapping are passed through unchanged.
// Token-like strings with unknown entity types are passed through unchanged.
// Text containing no tokens is returned byte-for-byte identical.
//
// Never panics or returns errors for invalid input.
func (t *Tokenizer) Rehydrate(text string) string {
	if text == "" {
		return text
	}

	matches := tokenRegex.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return text
	}

	var buf strings.Builder
	buf.Grow(len(text))
	lastEnd := 0

	for _, m := range matches {
		start, end := m[0], m[1]
		token := text[start:end]

		// Write text before the token.
		if start > lastEnd {
			buf.WriteString(text[lastEnd:start])
		}

		// Look up the token in the store.
		if piiValue, ok := t.store.Get(token); ok {
			buf.WriteString(piiValue)
		} else {
			// Token not in mapping — pass through unchanged.
			buf.WriteString(token)
		}

		lastEnd = end
	}

	// Write remaining text after the last token.
	if lastEnd < len(text) {
		buf.WriteString(text[lastEnd:])
	}

	return buf.String()
}

// Reset clears all token↔PII mappings and resets counters to zero.
// After Reset, previous tokens will resolve to nothing during rehydration.
// Safe to call concurrently with other operations.
func (t *Tokenizer) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.valueToToken = make(map[string]string)
	t.counters = make(map[pii.EntityType]uint64)
	t.store.Clear()

	// Log at debug level only — no PII, just metadata.
	t.logger.Debug("tokenizer state reset", "pii_values_logged", false)
}

// Count returns the number of tokens currently stored.
func (t *Tokenizer) Count() int {
	return t.store.Count()
}

// Close releases resources held by the tokenizer and its underlying store.
// After Close, the tokenizer should not be used.
func (t *Tokenizer) Close() error {
	return t.store.Close()
}

// isKnownEntityType returns true if the given type is one of the recognized types.
func isKnownEntityType(et pii.EntityType) bool {
	return knownEntityTypes[et]
}

// validateEntities filters and validates entities from the engine.
// Skips entities with invalid bounds or unknown types (defense-in-depth).
func validateEntities(entities []pii.Entity, textLen int) []pii.Entity {
	valid := make([]pii.Entity, 0, len(entities))
	for _, e := range entities {
		// Defense-in-depth: validate entity bounds.
		if e.Start < 0 || e.End <= e.Start || e.End > textLen {
			continue
		}
		// Validate entity type is known.
		if !isKnownEntityType(e.Type) {
			continue
		}
		valid = append(valid, e)
	}
	return valid
}

// substituteEntities replaces PII spans with tokens in the original text.
//
// Entities from the Engine are guaranteed non-overlapping and sorted by Start
// ascending. We build the result left-to-right with a strings.Builder, which is
// equivalent to right-to-left mutable-buffer replacement since the original
// string is immutable and byte offsets are never invalidated by prior
// substitutions.
func substituteEntities(text string, entities []pii.Entity, tokens []string) string {
	if len(entities) == 0 {
		return text
	}

	type pair struct {
		start, end int
		token      string
	}
	pairs := make([]pair, len(entities))
	for i := range entities {
		pairs[i] = pair{
			start: entities[i].Start,
			end:   entities[i].End,
			token: tokens[i],
		}
	}

	// Sort ascending for left-to-right builder iteration.
	// Defense-in-depth: Engine output is already sorted, but we sort anyway
	// in case a future caller violates the contract.
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].start < pairs[j].start
	})

	var buf strings.Builder
	pos := 0
	for _, p := range pairs {
		if p.start < pos {
			continue // skip overlapping/out-of-order entity (defense-in-depth)
		}
		if p.start > pos {
			buf.WriteString(text[pos:p.start])
		}
		buf.WriteString(p.token)
		pos = p.end
	}
	if pos < len(text) {
		buf.WriteString(text[pos:])
	}

	return buf.String()
}
