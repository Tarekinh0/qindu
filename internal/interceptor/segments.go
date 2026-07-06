package interceptor

import (
	"bytes"

	"github.com/Tarekinh0/qindu/internal/providers"
)

// replaceSegments replaces original text in body with segment text (now tokenized/rehydrated).
//
// Segments must be non-overlapping and sorted by Start ascending (engine guarantees this).
// Processing is right-to-left (descending Start) to handle token/PII length differences
// without invalidating byte offsets.
//
// Parameters:
//   - body: the original body bytes (never modified — a copy is returned)
//   - segments: text segments whose Text has been modified (tokenized or rehydrated),
//     and whose Start/End reference positions in the original body
//
// Returns a new byte slice with replacements applied. Returns a copy of body unchanged
// if no segments or no changes.
func replaceSegments(body []byte, segments []providers.TextSegment) []byte {
	if len(segments) == 0 {
		// Fast path: no segments to replace.
		out := make([]byte, len(body))
		copy(out, body)
		return out
	}

	// Validate segments and sort descending by Start for right-to-left processing.
	valid := make([]providers.TextSegment, 0, len(segments))
	for _, seg := range segments {
		if seg.Start < 0 || seg.End <= seg.Start || seg.End > len(body) {
			continue // skip invalid
		}
		// Also skip segments where text is identical (no-op).
		if string(body[seg.Start:seg.End]) == seg.Text {
			continue
		}
		valid = append(valid, seg)
	}

	if len(valid) == 0 {
		out := make([]byte, len(body))
		copy(out, body)
		return out
	}

	// Sort right-to-left (descending Start) for safe offset-independent replacement.
	// This is defense-in-depth: even though segments should already be sorted
	// ascending by the engine, we re-sort descending for replacement.
	sortSegmentsDesc(valid)

	// Create a mutable copy of the body.
	result := make([]byte, len(body))
	copy(result, body)

	for _, seg := range valid {
		origLen := seg.End - seg.Start
		newLen := len(seg.Text)

		if newLen == origLen {
			// Same length: direct copy.
			copy(result[seg.Start:seg.End], []byte(seg.Text))
		} else {
			// Different length: reconstruct the buffer.
			// Since we process right-to-left, offsets before seg.Start are still valid.
			var buf bytes.Buffer
			buf.Grow(len(result) - origLen + newLen)
			buf.Write(result[:seg.Start])
			buf.WriteString(seg.Text)
			buf.Write(result[seg.End:])
			result = buf.Bytes()
		}
	}

	return result
}

// sortSegmentsDesc sorts segments by Start descending for right-to-left processing.
func sortSegmentsDesc(segments []providers.TextSegment) {
	// Simple insertion sort for small slices (typical: <10 segments).
	for i := 1; i < len(segments); i++ {
		j := i
		for j > 0 && segments[j-1].Start < segments[j].Start {
			segments[j-1], segments[j] = segments[j], segments[j-1]
			j--
		}
	}
}
