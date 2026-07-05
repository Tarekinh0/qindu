package chatgpt

import (
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// parsePath tests
// =============================================================================

func TestParsePath_Valid(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "root path (empty)",
			path: "",
			want: []string{""},
		},
		{
			name: "single segment",
			path: "/message",
			want: []string{"", "message"},
		},
		{
			name: "content/parts with index",
			path: "/message/content/parts/0",
			want: []string{"", "message", "content", "parts", "0"},
		},
		{
			name: "deeply nested path",
			path: "/a/b/c/d/e",
			want: []string{"", "a", "b", "c", "d", "e"},
		},
		{
			name: "JSON Pointer escaped tilde",
			path: "/foo~0bar",
			want: []string{"", "foo~bar"},
		},
		{
			name: "JSON Pointer escaped slash",
			path: "/foo~1bar",
			want: []string{"", "foo/bar"},
		},
		{
			name: "numeric segment",
			path: "/content/parts/42",
			want: []string{"", "content", "parts", "42"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePath(tt.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("segment count mismatch: got %d, want %d (%v)", len(got), len(tt.want), got)
			}
			for i, seg := range got {
				if seg != tt.want[i] {
					t.Errorf("segment[%d] = %q, want %q", i, seg, tt.want[i])
				}
			}
		})
	}
}

func TestParsePath_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		errText string
	}{
		{
			name:    "missing leading slash",
			path:    "message/content",
			errText: "must start with '/'",
		},
		{
			name:    "extension prefix dollar-slash",
			path:    "/foo/$/secret",
			errText: "rejected extension prefix",
		},
		{
			name:    "extension prefix at-sign-slash",
			path:    "/foo/@/secret",
			errText: "rejected extension prefix",
		},
		{
			name: "path too long (>512 bytes)",
			// 10 chars * 52 + 1 ('/') = 521 bytes, exceeds maxPathTotalLen (512)
			path:    "/" + strings.Repeat("abcdefghij", 52),
			errText: "exceeds max length",
		},
		{
			name:    "segment too long (>256 bytes)",
			path:    "/" + strings.Repeat("x", 257),
			errText: "segment exceeds max length",
		},
		{
			name:    "depth too deep (>32 segments)",
			path:    "/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27/28/29/30/31/32/33",
			errText: "path depth",
		},
		{
			name:    "double-dot segment rejected",
			path:    "/foo/..",
			errText: "rejected '..' segment",
		},
		{
			name:    "path traversal style .. segments",
			path:    "/../../etc/passwd",
			errText: "rejected '..' segment",
		},
		{
			name:    "path without leading slash (relative)",
			path:    "foo/bar",
			errText: "must start with '/'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePath(tt.path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errText) {
				t.Errorf("error %q should contain %q", err.Error(), tt.errText)
			}
		})
	}
}

func TestParsePath_DeepButValid(t *testing.T) {
	// 31 segments + root = 32 total — exactly at the maxDepth boundary.
	parts := make([]string, 31)
	for i := range parts {
		parts[i] = "a"
	}
	path := "/" + strings.Join(parts, "/")
	segs, err := parsePath(path)
	if err != nil {
		t.Fatalf("unexpected error for 32-depth path: %v", err)
	}
	if len(segs) != 32 { // root + 31 segments
		t.Errorf("expected 32 segments, got %d", len(segs))
	}
}

func TestParsePath_ExactlyMaxTotalLen(t *testing.T) {
	// 512 bytes exactly (the max) should be accepted.
	// Use 8 segments of 63 chars each: 8*63 + 7('/') + 1(leading '/') = 504+7+1=512.
	seg63 := strings.Repeat("a", 63)
	path := "/" + strings.Join([]string{seg63, seg63, seg63, seg63, seg63, seg63, seg63, seg63}, "/")
	if len(path) != 512 {
		t.Fatalf("test setup wrong: path len=%d, want 512", len(path))
	}
	segs, err := parsePath(path)
	if err != nil {
		t.Errorf("unexpected error for 512-byte path: %v", err)
	}
	_ = segs
}

// =============================================================================
// isTextContentPath tests
// =============================================================================

func TestIsTextContentPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "exact content/parts/0", path: "/content/parts/0", want: true},
		{name: "message content/parts/0", path: "/message/content/parts/0", want: true},
		{name: "deeply nested parts", path: "/a/b/content/parts/3", want: true},
		{name: "content/parts with large index", path: "/content/parts/999", want: true},
		{name: "content/parts/ without index", path: "/content/parts/", want: false},
		{name: "just content", path: "/content", want: false},
		{name: "content/parts as substring", path: "/somethingcontent/parts/0", want: false},
		{name: "empty path", path: "", want: false},
		{name: "metadata path", path: "/message/metadata", want: false},
		{name: "status path", path: "/message/status", want: false},
		{name: "end_turn path", path: "/message/end_turn", want: false},
		{name: "parts deeper (sub-index)", path: "/content/parts/0/sub", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTextContentPath(tt.path)
			if got != tt.want {
				t.Errorf("isTextContentPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// =============================================================================
// unescapePathSegment tests
// =============================================================================

func TestUnescapePathSegment(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "no escapes", input: "foo", want: "foo"},
		{name: "tilde escape ~0", input: "foo~0bar", want: "foo~bar"},
		{name: "slash escape ~1", input: "foo~1bar", want: "foo/bar"},
		{name: "both escapes", input: "a~0b~1c", want: "a~b/c"},
		{name: "multiple tildes", input: "~0~0", want: "~~"},
		{name: "multiple slashes", input: "~1~1", want: "//"},
		{name: "empty string", input: "", want: ""},
		{name: "only ~0", input: "~0", want: "~"},
		{name: "only ~1", input: "~1", want: "/"},
		{name: "~0 before ~1 applies correctly", input: "x~0~1y", want: "x~/y"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unescapePathSegment(tt.input)
			if got != tt.want {
				t.Errorf("unescapePathSegment(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// =============================================================================
// setAt tests — resource boundaries and edge cases
// =============================================================================

func TestSetAt_MapInsert(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)

	result, err := tree.setAt(m, "message", map[string]any{"content": "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify the key was set on the original map.
	if _, exists := m["message"]; !exists {
		t.Error("setAt on map should set key on original map")
	}
	_ = result
	if tree.nodeCount != 1 {
		t.Errorf("expected nodeCount=1, got %d", tree.nodeCount)
	}
}

func TestSetAt_NonContainerNode(t *testing.T) {
	tree := newPatchTree()

	_, err := tree.setAt("not_a_container", "key", "value")
	if err == nil {
		t.Fatal("expected error setting on non-container node")
	}
	if !strings.Contains(err.Error(), "non-container node") {
		t.Errorf("error should mention non-container: %v", err)
	}
}

func TestSetAt_ArrayExtensionWithNilPadding(t *testing.T) {
	tree := newPatchTree()
	arr := []any{"a", "b"} // indices 0, 1

	// Set index 3 — should pad with nil at index 2.
	result, err := tree.setAt(arr, "3", "d")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	extended, ok := result.([]any)
	if !ok {
		t.Fatal("result should be a slice")
	}
	if len(extended) != 4 {
		t.Errorf("expected length 4, got %d", len(extended))
	}
	if extended[3] != "d" {
		t.Errorf("expected 'd' at index 3, got %v", extended[3])
	}
	if extended[2] != nil {
		t.Errorf("expected nil padding at index 2, got %v", extended[2])
	}
	// Node count: 2 new nodes (nil at idx 2, "d" at idx 3).
	if tree.nodeCount != 2 {
		t.Errorf("expected nodeCount=2 (for nil + value), got %d", tree.nodeCount)
	}
}

func TestSetAt_AppendBeyondBounds(t *testing.T) {
	tree := newPatchTree()
	arr := []any{}

	// Append at index 5 — should create 6 elements with nil padding.
	result, err := tree.setAt(arr, "5", "far")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	extended := result.([]any)
	if len(extended) != 6 {
		t.Errorf("expected length 6, got %d", len(extended))
	}
	for i := range 5 {
		if extended[i] != nil {
			t.Errorf("expected nil at index %d, got %v", i, extended[i])
		}
	}
	if extended[5] != "far" {
		t.Errorf("expected 'far' at index 5, got %v", extended[5])
	}
}

func TestSetAt_InvalidArrayIndex(t *testing.T) {
	tree := newPatchTree()
	arr := []any{"a"}

	_, err := tree.setAt(arr, "not_a_number", "value")
	if err == nil {
		t.Fatal("expected error for non-numeric array index")
	}
}

func TestSetAt_MaxTreeNodesExceededInMap(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)

	// Fill to the brim.
	for i := 0; i < maxTreeNodes; i++ {
		// Generate unique keys using rune-based patterns.
		key := fmt.Sprintf("k%d_%s", i, strings.Repeat("n", i%50))
		_, err := tree.setAt(m, key, i)
		if err != nil {
			t.Fatalf("unexpected error at node %d: %v", i, err)
		}
	}

	// Next insertion should fail.
	_, err := tree.setAt(m, "overflow_key_that_exceeds_limit", "too_many")
	if err == nil {
		t.Fatal("expected error after maxTreeNodes, got nil")
	}
	if !strings.Contains(err.Error(), "max node count") {
		t.Errorf("error should mention max node count: %v", err)
	}
}

func TestSetAt_MaxTreeNodesExceededInArray(t *testing.T) {
	tree := newPatchTree()
	arr := []any{}

	// maxTreeNodes = 10000. Extending to index 10001 requires 10002 nodes.
	_, err := tree.setAt(arr, fmt.Sprintf("%d", maxTreeNodes+1), "value")
	if err == nil {
		t.Fatal("expected error extending array beyond maxTreeNodes")
	}
}

func TestSetAt_OnNonExistentPath(t *testing.T) {
	// setAt on an int should fail with "non-container node".
	tree := newPatchTree()

	_, err := tree.setAt(42, "key", "value")
	if err == nil {
		t.Fatal("expected error for int parent")
	}
	if !strings.Contains(err.Error(), "non-container node") {
		t.Errorf("error should mention non-container: %v", err)
	}
}

// =============================================================================
// resolveParent tests
// =============================================================================

func TestResolveParent_PathTooShort(t *testing.T) {
	tree := newPatchTree()
	segs := []string{""} // only root

	_, _, _, err := tree.resolveParent(segs)
	if err == nil {
		t.Fatal("expected error for path with only root segment")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error should mention 'too short': %v", err)
	}
}

func TestResolveParent_TwoSegments(t *testing.T) {
	// resolveParent requires at least 3 segments: root, parent, last.
	// With 2 segments (root + one), len=2, lastSeg=segs[1], parentKey=segs[0]="",
	// containerSegs=segs[:0]=[]. The function loops over empty containerSegs,
	// current=root, and since root is a map, it succeeds.
	// This is a valid edge case — the container is the root itself.
	tree := newPatchTree()
	m := tree.root.(map[string]any)
	m["message"] = map[string]any{"text": "hello"}

	segs := []string{"", "message"} // root + "message"
	container, parentKey, lastSeg, err := tree.resolveParent(segs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parentKey != "" {
		t.Errorf("expected parentKey='' (root-level), got %q", parentKey)
	}
	if lastSeg != "message" {
		t.Errorf("expected lastSeg='message', got %q", lastSeg)
	}
	// container should be root map (contains "message").
	if _, ok := container.(map[string]any)["message"]; !ok {
		t.Error("expected container to be root map")
	}
}

func TestResolveParent_ThreeSegments(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)
	m["message"] = map[string]any{
		"content": map[string]any{
			"parts": []any{"text goes here"},
		},
	}

	segs := []string{"", "message", "content"}
	container, parentKey, lastSeg, err := tree.resolveParent(segs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parentKey != "message" {
		t.Errorf("expected parentKey='message', got %q", parentKey)
	}
	if lastSeg != "content" {
		t.Errorf("expected lastSeg='content', got %q", lastSeg)
	}
	// Verify container is the root map.
	if _, exists := container.(map[string]any)["message"]; !exists {
		t.Error("expected container to be root map (should contain 'message' key)")
	}
}

func TestResolveParent_MissingIntermediateSegment(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)
	m["message"] = map[string]any{}

	// To trigger the "not found" error during traversal, the missing segment
	// must be in containerSegs (not parentKey), and it must be non-empty.
	// With 4 segments: ["", "message", "nonexistent", "value"]
	// containerSegs = ["", "message"] → skip "", then getAt(root, "message") → found (existing map).
	// To truly miss: the intermediate must not exist.
	// Use: ["", "missing_intermediate", "child", "value"]
	// containerSegs = ["", "missing_intermediate"] → skip "", getAt(root, "missing_intermediate") → nil → error!
	segs := []string{"", "missing_intermediate", "child", "value"}
	_, _, _, err := tree.resolveParent(segs)
	if err == nil {
		t.Fatal("expected error for missing intermediate segment in traversal")
	}
}

func TestResolveParent_DeeplyNested(t *testing.T) {
	tree := newPatchTree()
	// Build: root → a → b → c → d
	m := tree.root.(map[string]any)
	m["a"] = map[string]any{
		"b": map[string]any{
			"c": map[string]any{"d": "leaf"},
		},
	}

	segs := []string{"", "a", "b", "c"}
	container, parentKey, lastSeg, err := tree.resolveParent(segs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parentKey != "b" {
		t.Errorf("expected parentKey='b', got %q", parentKey)
	}
	if lastSeg != "c" {
		t.Errorf("expected lastSeg='c', got %q", lastSeg)
	}
	_ = container
}

func TestResolveParent_ContainerNotAMap(t *testing.T) {
	// resolveParent has a safety check that the container is a map.
	// When root is an array, the traversal ends with a non-map container.
	tree := newPatchTree()
	tree.root = []any{"something"} // root is an array, not a map

	segs := []string{"", "0", "nonexistent"}
	// Traverse: containerSegs=[""], loop skips empty, current=root ([]any).
	// Then check: map[string]any assertion on []any fails → error.
	_, _, _, err := tree.resolveParent(segs)
	if err == nil {
		t.Fatal("expected error when container is not a map")
	}
	if !strings.Contains(err.Error(), "container is not a map") {
		t.Errorf("error should mention 'container is not a map': %v", err)
	}
}

// =============================================================================
// Resource boundary tests
// =============================================================================

func TestApplyOps_MaxTreeNodesDegradedMode(t *testing.T) {
	tree := newPatchTree()

	// Build nodes until we exhaust the tree.
	ops := make([]patchOp, 0, maxTreeNodes+10)
	for i := 0; i < maxTreeNodes+10; i++ {
		key := fmt.Sprintf("k%d_%s", i, strings.Repeat("x", i%50))
		ops = append(ops, patchOp{
			Op:    "add",
			Path:  "/" + key,
			Value: "v",
		})
	}

	tree.applyOps(ops)
	if !tree.degraded {
		t.Fatal("expected tree to be in degraded mode after exceeding maxTreeNodes")
	}
}

func TestApplyOps_MaxDepthError(t *testing.T) {
	tree := newPatchTree()

	// Build a path with maxPathDepth+1 segments (excluding root).
	parts := make([]string, maxPathDepth+1)
	for i := range parts {
		parts[i] = "a"
	}
	deepPath := "/" + strings.Join(parts, "/")

	ops := []patchOp{
		{Op: "add", Path: deepPath, Value: "should_fail"},
	}

	text, err := tree.applyOps(ops)
	if err == nil {
		t.Fatal("expected error for path exceeding max depth")
	}
	if text != "" {
		t.Errorf("expected no extracted text on error, got %q", text)
	}
	if !tree.degraded {
		t.Fatal("expected tree to be in degraded mode after error")
	}
}

func TestApplyOps_MaxCumulativeTextDegradedMode(t *testing.T) {
	tree := newPatchTree()

	// The cumulative text tracker counts text added to content/parts paths.
	// Add text chunks to exceed maxCumulativeText (1 MiB).
	// Each chunk 100 KiB, need enough to go over 1 MiB.
	chunkSize := 100 * 1024
	chunksNeeded := (maxCumulativeText / chunkSize) + 2

	ops := make([]patchOp, 0, chunksNeeded)
	for i := 0; i < chunksNeeded; i++ {
		text := strings.Repeat("x", chunkSize)
		ops = append(ops, patchOp{
			Op:    "add",
			Path:  "/content/parts/" + fmt.Sprintf("%d", i),
			Value: text,
		})
	}

	_, _ = tree.applyOps(ops)

	if !tree.degraded {
		// Tree might have hit the node limit first. Try an append to existing path
		// with a huge value to specifically trigger the text limit.
		if tree.cumulativeText <= maxCumulativeText {
			extraOps := []patchOp{
				{Op: "append", Path: "/content/parts/" + fmt.Sprintf("%d", chunksNeeded-1), Value: strings.Repeat("y", maxCumulativeText)},
			}
			tree.applyOps(extraOps)
			if !tree.degraded {
				t.Error("expected degraded mode after cumulative text overflow")
			}
		}
	}
}

func TestApplyOps_MaxSegmentLenError(t *testing.T) {
	tree := newPatchTree()

	// Create a segment longer than maxPathSegmentLen (256).
	longSegment := strings.Repeat("x", maxPathSegmentLen+1)
	ops := []patchOp{
		{Op: "add", Path: "/" + longSegment, Value: "value"},
	}

	text, err := tree.applyOps(ops)
	if err == nil {
		t.Fatal("expected error for segment exceeding max length")
	}
	if !strings.Contains(err.Error(), "segment exceeds max length") {
		t.Errorf("error should mention segment length: %v", err)
	}
	if text != "" {
		t.Errorf("expected no extracted text on error, got %q", text)
	}
	if !tree.degraded {
		t.Fatal("expected tree to be in degraded mode after error")
	}
}

func TestApplyOps_PathTooLongError(t *testing.T) {
	tree := newPatchTree()

	// Path of maxPathTotalLen+1 (513 bytes).
	longPath := "/" + strings.Repeat("a", maxPathTotalLen)
	ops := []patchOp{
		{Op: "add", Path: longPath, Value: "value"},
	}

	text, err := tree.applyOps(ops)
	if err == nil {
		t.Fatal("expected error for path exceeding max total length")
	}
	if !strings.Contains(err.Error(), "exceeds max length") {
		t.Errorf("error should mention max length: %v", err)
	}
	if text != "" {
		t.Errorf("expected no extracted text on error, got %q", text)
	}
	if !tree.degraded {
		t.Fatal("expected tree to be in degraded mode after error")
	}
}

func TestApplyOps_AlreadyDegraded(t *testing.T) {
	tree := newPatchTree()
	tree.degraded = true

	ops := []patchOp{
		{Op: "add", Path: "/content/parts/0", Value: "should_not_be_extracted"},
	}

	text, err := tree.applyOps(ops)
	if err != nil {
		t.Errorf("applyOps on degraded tree should not error: %v", err)
	}
	if text != "" {
		t.Errorf("expected no text from degraded tree, got %q", text)
	}
}

// =============================================================================
// clear() tests
// =============================================================================

func TestClear_ResetsAllState(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)
	m["message"] = map[string]any{"text": "hello"}
	tree.nodeCount = 1
	tree.cumulativeText = 100
	tree.degraded = true

	tree.clear()

	if tree.root != nil {
		t.Fatal("expected nil root after clear")
	}
	if tree.nodeCount != 0 {
		t.Errorf("expected nodeCount=0, got %d", tree.nodeCount)
	}
	if tree.cumulativeText != 0 {
		t.Errorf("expected cumulativeText=0, got %d", tree.cumulativeText)
	}
	if tree.degraded {
		t.Error("expected degraded=false after clear")
	}
}

func TestClear_PostClearState(t *testing.T) {
	// After clear, the tree root is nil. Operations after clear on the
	// same tree would panic. The caller (chatGPTSession) guards against
	// this with the streamEnded flag. This test documents the post-clear state.
	tree := newPatchTree()
	tree.clear()

	if tree.root != nil {
		t.Fatal("root should be nil after clear")
	}
}

// =============================================================================
// stringValue tests
// =============================================================================

func TestStringValue(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "string", value: "hello", want: "hello"},
		{name: "empty string", value: "", want: ""},
		{name: "int", value: 42, want: ""},
		{name: "nil", value: nil, want: ""},
		{name: "bool", value: true, want: ""},
		{name: "float", value: 3.14, want: ""},
		{name: "slice", value: []any{"a"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stringValue(tt.value)
			if got != tt.want {
				t.Errorf("stringValue(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// =============================================================================
// sanitizePathForError tests
// =============================================================================

func TestSanitizePathForError(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "short path", path: "/foo", want: "/foo"},
		{name: "exactly 40 chars", path: "/" + strings.Repeat("a", 39), want: "/" + strings.Repeat("a", 39)},
		{name: "long path truncated", path: "/" + strings.Repeat("a", 100), want: "/" + strings.Repeat("a", 39) + "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizePathForError(tt.path)
			if got != tt.want {
				t.Errorf("sanitizePathForError(%q) = %q (len=%d), want %q (len=%d)",
					tt.path, got, len(got), tt.want, len(tt.want))
			}
		})
	}
}

// =============================================================================
// sanitizeSegmentForError tests
// =============================================================================

func TestSanitizeSegmentForError(t *testing.T) {
	tests := []struct {
		name string
		seg  string
		want string
	}{
		{name: "short segment", seg: "abc", want: "abc"},
		{name: "exactly 20 chars", seg: strings.Repeat("x", 20), want: strings.Repeat("x", 20)},
		{name: "long segment truncated", seg: strings.Repeat("x", 50), want: strings.Repeat("x", 20) + "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeSegmentForError(tt.seg)
			if got != tt.want {
				t.Errorf("sanitizeSegmentForError(%q) = %q, want %q", tt.seg, got, tt.want)
			}
		})
	}
}

// =============================================================================
// getAt tests
// =============================================================================

func TestGetAt(t *testing.T) {
	m := map[string]any{
		"key1": "val1",
		"key2": 42,
	}
	arr := []any{"a", "b", "c"}

	tests := []struct {
		name string
		node any
		seg  string
		want any
	}{
		{name: "map key exists", node: m, seg: "key1", want: "val1"},
		{name: "map key missing", node: m, seg: "nonexistent", want: nil},
		{name: "array valid index", node: arr, seg: "1", want: "b"},
		{name: "array OOB", node: arr, seg: "999", want: nil},
		{name: "array negative index", node: arr, seg: "-1", want: nil},
		{name: "string node", node: "not a container", seg: "anything", want: nil},
		{name: "int node", node: 42, seg: "anything", want: nil},
		{name: "invalid array index", node: arr, seg: "abc", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getAt(tt.node, tt.seg)
			if got != tt.want {
				t.Errorf("getAt(%v, %q) = %v, want %v", tt.node, tt.seg, got, tt.want)
			}
		})
	}
}

// =============================================================================
// walkAndSet tests
// =============================================================================

func TestWalkAndSet_ArrayReallocationWriteBack(t *testing.T) {
	// ChatGPT usage pattern: content/parts is an array stored inside a map node.
	// Test that array extension via walkAndSet properly writes back the
	// reallocated slice to the containing map.
	tree := newPatchTree()
	m := tree.root.(map[string]any)

	// Set up: root → container → arr (simulating message → content → parts).
	// Path: /container/arr → value. WalkAndSet creates intermediate maps.
	m["container"] = map[string]any{
		"arr": []any{"first"},
	}

	// Add an element at index 5 of the array (requires extension + nil padding).
	// The fix to walkAndSet (removing the incomparable slice comparison) ensures
	// the reallocated array is always written back when the parent is an array.
	segs := []string{"", "container", "arr", "5"}
	_, err := tree.walkAndSet(segs, "fifth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the array was extended in place via write-back.
	container, ok := m["container"].(map[string]any)
	if !ok {
		t.Fatal("container should still be a map")
	}
	arr, ok := container["arr"].([]any)
	if !ok {
		t.Fatal("arr should still be []any")
	}
	if len(arr) != 6 {
		t.Errorf("expected array length 6, got %d", len(arr))
	}
	if arr[0] != "first" {
		t.Errorf("expected 'first' at index 0, got %v", arr[0])
	}
	if arr[5] != "fifth" {
		t.Errorf("expected 'fifth' at index 5, got %v", arr[5])
	}
}

func TestWalkAndSet_DeeplyNested(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)

	// Create a deeply nested path: /a/b/c/d/e/f → value.
	segs := []string{"", "a", "b", "c", "d", "e", "f"}
	_, err := tree.walkAndSet(segs, "deep_value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the chain exists.
	a, ok := m["a"].(map[string]any)
	if !ok {
		t.Fatal("a should be a map")
	}
	b, ok := a["b"].(map[string]any)
	if !ok {
		t.Fatal("b should be a map")
	}
	c, ok := b["c"].(map[string]any)
	if !ok {
		t.Fatal("c should be a map")
	}
	d, ok := c["d"].(map[string]any)
	if !ok {
		t.Fatal("d should be a map")
	}
	e, ok := d["e"].(map[string]any)
	if !ok {
		t.Fatal("e should be a map")
	}
	f, ok := e["f"]
	if !ok {
		t.Fatal("f should exist")
	}
	if f != "deep_value" {
		t.Errorf("expected 'deep_value', got %v", f)
	}
}

// =============================================================================
// applyOps with unsupported "patch" batch op
// =============================================================================

func TestApplyOps_PatchBatch(t *testing.T) {
	tree := newPatchTree()

	ops := []patchOp{
		{
			Op: "patch",
			Ops: []patchOp{
				{Op: "add", Path: "/content/parts/0", Value: "text from batch"},
				{Op: "add", Path: "/content/parts/1", Value: "more text"},
			},
		},
	}

	text, err := tree.applyOps(ops)
	if err != nil {
		t.Fatalf("unexpected error from patch batch: %v", err)
	}
	if text != "text from batchmore text" {
		t.Errorf("expected concatenated text, got %q", text)
	}
	if tree.degraded {
		t.Error("tree should not be degraded after valid batch patch")
	}
}

func TestApplyOps_UnknownOpSilentlySkipped(t *testing.T) {
	tree := newPatchTree()

	ops := []patchOp{
		{Op: "", Path: "/content/parts/0", Value: "noop_text"},
	}

	text, err := tree.applyOps(ops)
	if err != nil {
		t.Fatalf("unexpected error from unknown op: %v", err)
	}
	if text != "" {
		t.Errorf("expected empty text for unknown op, got %q", text)
	}
}

// =============================================================================
// handleAdd applies to content/parts path — text extraction
// =============================================================================

func TestHandleAdd_TextExtraction(t *testing.T) {
	tree := newPatchTree()

	// Adding text to a content/parts path should extract it.
	text, err := tree.handleAdd(patchOp{
		Op:    "add",
		Path:  "/message/content/parts/0",
		Value: "hello@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if text != "hello@example.com" {
		t.Errorf("expected extracted text, got %q", text)
	}
}

func TestHandleAdd_NonTextPathNoExtraction(t *testing.T) {
	tree := newPatchTree()

	// Adding to a non-text path should not extract text.
	text, err := tree.handleAdd(patchOp{
		Op:    "add",
		Path:  "/message/status",
		Value: "finished",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if text != "" {
		t.Errorf("expected no extracted text for non-text path, got %q", text)
	}
}

// =============================================================================
// handleReplace — text content path
// =============================================================================

func TestHandleReplace_TextPath(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)
	m["message"] = map[string]any{
		"content": map[string]any{
			"parts": []any{"old text"},
		},
	}

	text, err := tree.handleReplace(patchOp{
		Op:    "replace",
		Path:  "/message/content/parts/0",
		Value: "new text with pii@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if text != "new text with pii@example.com" {
		t.Errorf("expected extracted text on replace, got %q", text)
	}
}

// =============================================================================
// handleAppend — text content path
// =============================================================================

func TestHandleAppend_TextPath(t *testing.T) {
	tree := newPatchTree()
	m := tree.root.(map[string]any)
	m["message"] = map[string]any{
		"content": map[string]any{
			"parts": []any{"Hello! "},
		},
	}

	text, err := tree.handleAppend(patchOp{
		Op:    "append",
		Path:  "/message/content/parts/0",
		Value: "my email is john@doe.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if text != "my email is john@doe.com" {
		t.Errorf("expected appended text, got %q", text)
	}

	// Verify the tree was updated.
	container, _ := m["message"].(map[string]any)["content"].(map[string]any)
	arr, _ := container["parts"].([]any)
	if arr[0] != "Hello! my email is john@doe.com" {
		t.Errorf("expected concatenated value, got %q", arr[0])
	}
}
