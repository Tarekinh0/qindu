// Package chatgpt implements the ChatGPT web provider plugin for Qindu.
package chatgpt

import (
	"fmt"
	"strconv"
	"strings"
)

// Resource limits for the JSON Patch document tree (CS-11-03).
const (
	maxTreeNodes      = 10000   // Max nodes per stream
	maxPathDepth      = 32      // Max path segments
	maxPathSegmentLen = 256     // Max bytes per path segment
	maxPathTotalLen   = 512     // Max total path length in bytes (CS-11-04)
	maxCumulativeText = 1 << 20 // 1 MiB max cumulative text in tree
)

// textContentPathSuffix is the suffix that identifies text content paths.
// ChatGPT text lives at */content/parts/* — any path matching this suffix
// triggers text extraction.
const textContentPathSuffix = "/content/parts/"

// patchOp is a single JSON Patch operation.
type patchOp struct {
	Op    string    `json:"o"`   // "add", "append", "replace", "patch"
	Path  string    `json:"p"`   // JSON Pointer path
	Value any       `json:"v"`   // value to add/append/replace
	Ops   []patchOp `json:"ops"` // sub-operations for "patch"
}

// patchTree is a minimal JSON Patch document tree state machine.
// It maintains an in-memory tree sufficient to resolve content/parts paths.
// Full JSON Patch conformance is not required — only the subset used by ChatGPT.
//
// All fields are unexported (DPO-R2.1: never serialized to disk or exposed).
type patchTree struct {
	root           any  // root node (map[string]any)
	nodeCount      int  // current number of nodes
	cumulativeText int  // total text bytes accumulated
	degraded       bool // true when limits exceeded (CS-11-03)
}

// newPatchTree creates an empty document tree.
func newPatchTree() *patchTree {
	return &patchTree{
		root: make(map[string]any),
	}
}

// applyOps applies a slice of JSON Patch operations to the document tree.
// Returns extracted text from text-targeted operations, and any error.
func (t *patchTree) applyOps(ops []patchOp) (extractedText string, err error) {
	if t.degraded {
		return "", nil
	}
	for _, op := range ops {
		text, opErr := t.applyOp(op)
		if opErr != nil {
			// Individual operation errors trigger degraded mode.
			t.degraded = true
			return "", opErr
		}
		if text != "" {
			extractedText += text
		}
	}
	return extractedText, nil
}

// applyOp applies a single JSON Patch operation.
func (t *patchTree) applyOp(op patchOp) (extractedText string, err error) {
	switch op.Op {
	case "add":
		return t.handleAdd(op)
	case "append":
		return t.handleAppend(op)
	case "replace":
		return t.handleReplace(op)
	case "patch":
		return t.applyOps(op.Ops)
	default:
		return "", nil // unknown ops are silently skipped
	}
}

// handleAdd adds a value at the given path, creating intermediate nodes as needed.
// Tree-traversal-and-write-back logic is extracted into walkAndSet (PR-101).
func (t *patchTree) handleAdd(op patchOp) (string, error) {
	segs, err := parsePath(op.Path)
	if err != nil {
		return "", err
	}

	_, err = t.walkAndSet(segs, op.Value)
	if err != nil {
		return "", err
	}

	// If this is adding to a content/parts path, the value is new text.
	if isTextContentPath(op.Path) {
		text := stringValue(op.Value)
		t.cumulativeText += len(text)
		if t.cumulativeText > maxCumulativeText {
			t.degraded = true
			return text, fmt.Errorf("cumulative text exceeds limit")
		}
		return text, nil
	}

	return "", nil
}

// walkAndSet traverses the document tree along the given path segments, creating
// intermediate map nodes as needed, and sets the value at the final segment.
// It handles array reallocation write-back: when the target's immediate parent
// is an array and setAt extends it, the reallocated slice is written back to
// the containing map node.
//
// ChatGPT intermediate nodes are always maps because input_message initializes
// the tree before any JSON Patch operations arrive. Arrays (content.parts) are
// only leaf containers, not intermediate path segments.
func (t *patchTree) walkAndSet(segs []string, value any) (any, error) {
	current := t.root
	lastContainer := t.root
	lastContainerKey := ""
	finalParentIsMap := true // whether the final target's immediate parent is a map (vs array)

	for i, seg := range segs {
		if seg == "" {
			continue // root segment
		}
		if i == len(segs)-2 {
			// This is the parent — track the container context.
			lastContainer = current
			lastContainerKey = seg
			next := getAt(current, seg)
			if next == nil {
				newNode := make(map[string]any)
				if _, err := t.setAt(current, seg, newNode); err != nil {
					return nil, err
				}
				current = newNode
				finalParentIsMap = true
			} else {
				current = next
				_, finalParentIsMap = next.(map[string]any)
			}
		} else if i == len(segs)-1 {
			// Last segment — set the value.
			newParent, err := t.setAt(current, seg, value)
			if err != nil {
				return nil, err
			}
			// If the parent was an array, always write back since Go
			// slices are not comparable — array extension always reallocates.
			// The write-back is a no-op (existing key) when no reallocation occurred.
			if !finalParentIsMap {
				if _, err := t.setAt(lastContainer, lastContainerKey, newParent); err != nil {
					return nil, err
				}
			}
			return newParent, nil
		} else {
			// Intermediate segment — ensure it exists.
			next := getAt(current, seg)
			if next == nil {
				newNode := make(map[string]any)
				if _, err := t.setAt(current, seg, newNode); err != nil {
					return nil, err
				}
				next = newNode
			}
			current = next
		}
	}

	return nil, nil
}

// handleAppend appends text to a string value at the given path.
func (t *patchTree) handleAppend(op patchOp) (string, error) {
	return t.applyToResolvedPath(op, func(current any) (any, error) {
		currentStr, _ := current.(string)
		appendStr := stringValue(op.Value)
		return currentStr + appendStr, nil
	})
}

// handleReplace replaces a value at the given path.
func (t *patchTree) handleReplace(op patchOp) (string, error) {
	return t.applyToResolvedPath(op, func(_ any) (any, error) {
		return op.Value, nil
	})
}

// applyToResolvedPath resolves the path, retrieves the parent node, applies the
// transform function to the current value at the target segment, writes back
// the (possibly reallocated) parent to the container, and tracks cumulative
// text for text-content paths. Shared by handleAppend and handleReplace to
// eliminate structural duplication (PR-101).
//
// PR-103: For replace operations, tracks the old text length and adjusts
// cumulativeText by the delta (newLen - oldLen) instead of adding the full
// new length. This prevents premature degradation from over-counting.
func (t *patchTree) applyToResolvedPath(op patchOp, transform func(current any) (any, error)) (string, error) {
	segs, err := parsePath(op.Path)
	if err != nil {
		return "", err
	}

	container, parentKey, lastSeg, err := t.resolveParent(segs)
	if err != nil {
		return "", err
	}

	parent := getAt(container, parentKey)
	if parent == nil {
		return "", fmt.Errorf("parent %q not found", sanitizeSegmentForError(parentKey))
	}

	current := getAt(parent, lastSeg)
	newValue, err := transform(current)
	if err != nil {
		return "", err
	}

	// Update the target, getting the possibly reallocated parent.
	newParent, err := t.setAt(parent, lastSeg, newValue)
	if err != nil {
		return "", err
	}

	// Write back the (possibly reallocated) parent to the container.
	if _, err := t.setAt(container, parentKey, newParent); err != nil {
		return "", err
	}

	// Extract text only if this is a content/parts path.
	if isTextContentPath(op.Path) {
		text := stringValue(newValue)
		// For append operations, only count the appended portion.
		if op.Op == "append" {
			text = stringValue(op.Value)
		}
		// PR-103: For replace operations, track old text length and adjust.
		if op.Op == "replace" {
			oldText := stringValue(current)
			t.cumulativeText += len(text) - len(oldText)
		} else {
			t.cumulativeText += len(text)
		}
		if t.cumulativeText > maxCumulativeText {
			t.degraded = true
			return text, fmt.Errorf("cumulative text exceeds limit")
		}
		return text, nil
	}

	return "", nil
}

// parsePath parses a JSON Pointer path into segments.
// Returns an error if the path is invalid per CS-11-04.
func parsePath(path string) ([]string, error) {
	// Reject empty path.
	if len(path) == 0 {
		return []string{""}, nil // root path
	}

	// Reject paths exceeding max total length (CS-11-04).
	if len(path) > maxPathTotalLen {
		return nil, fmt.Errorf("path exceeds max length: %d", len(path))
	}

	// Path must start with / (RFC 6901).
	if path[0] != '/' {
		return nil, fmt.Errorf("path must start with '/': %q", sanitizePathForError(path))
	}

	// Split and validate segments.
	rawSegs := strings.Split(path[1:], "/")
	var segs []string
	segs = append(segs, "") // root
	for _, raw := range rawSegs {
		decoded := unescapePathSegment(raw)

		// Reject empty path segments (e.g., /foo//bar) (CS-11-04).
		if decoded == "" && raw != "" {
			return nil, fmt.Errorf("empty path segment in %q", sanitizePathForError(path))
		}

		// Reject segments starting with $ or @ (JSON Pointer extensions) (CS-11-04).
		if len(decoded) > 0 && (decoded[0] == '$' || decoded[0] == '@') {
			return nil, fmt.Errorf("rejected extension prefix in path %q segment %q", sanitizePathForError(path), sanitizeSegmentForError(decoded))
		}

		// Reject ".." segments — defense-in-depth (CS-11-04.1).
		// JSON Pointer has no traversal semantics, but rejecting ".." prevents
		// path-traversal-styled inputs from reaching downstream consumers.
		if decoded == ".." {
			return nil, fmt.Errorf("rejected '..' segment in path %q", sanitizePathForError(path))
		}

		// Reject segments exceeding max length.
		if len(decoded) > maxPathSegmentLen {
			return nil, fmt.Errorf("path segment exceeds max length: %d", len(decoded))
		}

		segs = append(segs, decoded)
	}

	// Reject paths with too many segments (CS-11-03).
	if len(segs) > maxPathDepth {
		return nil, fmt.Errorf("path depth %d exceeds max %d", len(segs), maxPathDepth)
	}

	return segs, nil
}

// resolveParent traverses the tree to the parent of the last segment.
// Returns the node containing the parent (container), the key/index of the parent
// within the container (parentKey), and the last segment name.
// The container is always a map[string]any for ChatGPT text paths; if the
// container is an array that would need reallocation, an error is returned.
func (t *patchTree) resolveParent(segs []string) (container any, parentKey string, lastSeg string, err error) {
	if len(segs) < 2 {
		return nil, "", "", fmt.Errorf("path too short for resolveParent: %d segments", len(segs))
	}

	lastSeg = segs[len(segs)-1]
	parentKey = segs[len(segs)-2]
	containerSegs := segs[:len(segs)-2]

	current := t.root
	for _, seg := range containerSegs {
		if seg == "" {
			continue
		}
		next := getAt(current, seg)
		if next == nil {
			return nil, "", "", fmt.Errorf("path segment %q not found", sanitizeSegmentForError(seg))
		}
		current = next
	}

	// Safety: container must be a map to support write-back of reallocated arrays.
	if _, ok := current.(map[string]any); !ok {
		return nil, "", "", fmt.Errorf("container is not a map, cannot safely write back array reallocations")
	}

	return current, parentKey, lastSeg, nil
}

// getAt retrieves a value from a node by segment.
// Handles both map keys and array indices.
// Returns nil for out-of-bounds array indices. Note: nil may also be returned
// for valid array indices that were populated with nil by setAt during array
// extension (see setAt doc). Callers must not rely on nil to distinguish
// "not found" from "found nil" without additional bounds checking.
func getAt(node any, seg string) any {
	switch n := node.(type) {
	case map[string]any:
		return n[seg]
	case []any:
		idx, err := strconv.Atoi(seg)
		if err != nil || idx < 0 || idx >= len(n) {
			return nil
		}
		return n[idx]
	}
	return nil
}

// setAt sets a value at a node's segment. Creates containers as needed.
// Returns the (possibly reallocated) parent node for write-back to the tree.
//
// When setting a value at an array index beyond the current length, the array
// is extended with nil padding to reach the target index. These nil entries
// persist in the tree and will be returned as nil by getAt. Callers that need
// to distinguish "never set" from "explicitly set to nil" should track array
// lengths separately.
func (t *patchTree) setAt(parent any, seg string, value any) (any, error) {
	switch p := parent.(type) {
	case map[string]any:
		existing := p[seg]
		if existing == nil {
			t.nodeCount++
			if t.nodeCount > maxTreeNodes {
				return nil, fmt.Errorf("max node count %d exceeded", maxTreeNodes)
			}
		}
		p[seg] = value
		return p, nil
	case []any:
		idx, err := strconv.Atoi(seg)
		if err != nil {
			return nil, fmt.Errorf("invalid array index %q", sanitizeSegmentForError(seg))
		}
		// Extend array if needed.
		for len(p) <= idx {
			p = append(p, nil)
			t.nodeCount++
			if t.nodeCount > maxTreeNodes {
				return nil, fmt.Errorf("max node count %d exceeded", maxTreeNodes)
			}
		}
		p[idx] = value
		return p, nil
	default:
		return nil, fmt.Errorf("cannot set on non-container node")
	}
}

// isTextContentPath returns true if the path targets text content.
// Text paths match: */content/parts/* (ends with /content/parts/<index> or deeper).
func isTextContentPath(path string) bool {
	// Must contain /content/parts/
	if !strings.Contains(path, textContentPathSuffix) {
		return false
	}
	// Ensure it's a path to a parts element, not just a parent.
	idx := strings.LastIndex(path, textContentPathSuffix)
	rest := path[idx+len(textContentPathSuffix):]
	return len(rest) > 0
}

// stringValue extracts a string from a value. Returns empty string for non-strings.
func stringValue(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// clear destroys the document tree by setting root to nil (DPO-R2.2).
func (t *patchTree) clear() {
	t.root = nil
	t.nodeCount = 0
	t.cumulativeText = 0
	t.degraded = false
}

// sanitizePathForError returns a shortened, safe version of a path for error logging.
// Never includes the full path content — only length and prefix.
func sanitizePathForError(path string) string {
	max := 40
	if len(path) <= max {
		return path
	}
	return path[:max] + "..."
}

// sanitizeSegmentForError returns a shortened version of a path segment for error logging.
func sanitizeSegmentForError(seg string) string {
	if len(seg) <= 20 {
		return seg
	}
	return seg[:20] + "..."
}

// unescapePathSegment unescapes JSON Pointer escape sequences (~0 → ~, ~1 → /).
func unescapePathSegment(s string) string {
	s = strings.ReplaceAll(s, "~1", "/")
	s = strings.ReplaceAll(s, "~0", "~")
	return s
}
