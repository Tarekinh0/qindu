package pii

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// DefaultMaxInputBytes is the default maximum input size (1 MiB).
const DefaultMaxInputBytes = 1 << 20 // 1,048,576

// ErrInputTooLarge is returned when an input exceeds the maximum allowed size.
// The message contains only sizes, never the input text.
type ErrInputTooLarge struct {
	MaxSize  int
	Received int
}

func (e *ErrInputTooLarge) Error() string {
	return fmt.Sprintf("input too large: max %d bytes, received %d bytes", e.MaxSize, e.Received)
}

// Engine orchestrates all recognizers, runs detection, and resolves overlaps.
// Safe for concurrent use.
type Engine struct {
	recognizers []Recognizer
	mu          sync.RWMutex
	maxInputLen int // reject inputs larger than this
}

// NewEngine creates a new detection engine with the given recognizers.
// Order matters for overlap resolution (first registered = higher priority
// when all other tiebreakers are equal).
//
// The EMAIL recognizer MUST be registered before the NAME recognizer —
// the NAME recognizer depends on EMAIL results.
func NewEngine(maxInputBytes int, recognizers ...Recognizer) *Engine {
	if maxInputBytes <= 0 {
		maxInputBytes = DefaultMaxInputBytes
	}
	return &Engine{
		recognizers: recognizers,
		maxInputLen: maxInputBytes,
	}
}

// Detect runs all recognizers, resolves overlapping spans, and returns
// deduplicated entities sorted by byte position.
//
// Safe for concurrent use.
func (e *Engine) Detect(text string) ([]Entity, error) {
	// Reject oversized inputs before any processing.
	if len(text) > e.maxInputLen {
		return nil, &ErrInputTooLarge{
			MaxSize:  e.maxInputLen,
			Received: len(text),
		}
	}

	// Acquire read lock for the duration of detection.
	e.mu.RLock()
	recognizers := make([]Recognizer, len(e.recognizers))
	copy(recognizers, e.recognizers)
	e.mu.RUnlock()

	if len(recognizers) == 0 {
		return nil, nil
	}

	// Phase 1: Run all recognizers EXCEPT NAME recognizer.
	// We run them sequentially for correctness (EMAIL must run before NAME).
	// Recognizers are stateless, so sequential execution is safe.
	var allEntities []Entity
	var emailEntities []Entity

	// Collect results from non-NAME recognizers.
	// We need to identify which recognizer is NAME so we can run it last.
	var nameIdx = -1
	for i, r := range recognizers {
		if r.Type() == Name {
			nameIdx = i
			continue
		}
		entities := r.Detect(text)
		if r.Type() == Email {
			emailEntities = append(emailEntities, entities...)
		}
		allEntities = append(allEntities, entities...)
	}

	// Phase 2: Run NAME recognizer with EMAIL entities if present.
	if nameIdx >= 0 {
		nameRecognizer := recognizers[nameIdx]
		if aware, ok := nameRecognizer.(EmailAwareRecognizer); ok {
			nameEntities := aware.DetectWithEmails(text, emailEntities)
			allEntities = append(allEntities, nameEntities...)
		} else {
			// Fallback to standard Detect if not EmailAware.
			nameEntities := nameRecognizer.Detect(text)
			allEntities = append(allEntities, nameEntities...)
		}
	}

	// Resolve overlaps.
	allEntities = resolveOverlaps(allEntities)

	// Sort final result by byte position.
	sort.Slice(allEntities, func(i, j int) bool {
		return allEntities[i].Start < allEntities[j].Start
	})

	if len(allEntities) == 0 {
		return nil, nil
	}

	return allEntities, nil
}

// IsInputTooLarge checks if an error is an ErrInputTooLarge.
func IsInputTooLarge(err error) bool {
	var e *ErrInputTooLarge
	return errors.As(err, &e)
}
