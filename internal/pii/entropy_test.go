package pii

import (
	"math"
	"testing"
)

func TestComputeEntropyEmptyString(t *testing.T) {
	if h := ComputeEntropy(""); h != 0.0 {
		t.Errorf("empty string entropy should be 0, got %f", h)
	}
}

func TestComputeEntropySingleChar(t *testing.T) {
	if h := ComputeEntropy("a"); h != 0.0 {
		t.Errorf("single char entropy should be 0, got %f", h)
	}
}

func TestComputeEntropyAllSameChar(t *testing.T) {
	if h := ComputeEntropy("aaaaaaaaaa"); h != 0.0 {
		t.Errorf("all same char entropy should be 0, got %f", h)
	}
}

func TestComputeEntropyUniform(t *testing.T) {
	// A string with 64 unique characters each appearing once should have
	// entropy ≈ log2(64) = 6.0
	s := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	h := ComputeEntropy(s)
	expected := math.Log2(64.0)
	if h < expected-0.05 || h > expected+0.05 {
		t.Errorf("uniform 64-char entropy ≈ %f, got %f", expected, h)
	}
}

func TestComputeEntropyBase64Random(t *testing.T) {
	// A truly random base64-like string should have high entropy.
	s := "dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHRoYXQgaXMgbG9uZyBlbm91Z2g="
	h := ComputeEntropy(s)
	if h < 3.0 {
		t.Errorf("base64-like string should have entropy > 3.0, got %f", h)
	}
}

func TestComputeEntropyEnglish(t *testing.T) {
	// English prose should have entropy around 3.0-4.0.
	s := "The quick brown fox jumps over the lazy dog multiple times today."
	h := ComputeEntropy(s)
	if h < 2.0 || h > 5.5 {
		t.Errorf("English prose entropy should be ~3-4, got %f", h)
	}
}

func TestComputeEntropyOverAlphabetEmpty(t *testing.T) {
	alpha := map[byte]bool{'A': true}
	if h := ComputeEntropyOverAlphabet("", alpha); h != 0.0 {
		t.Errorf("empty string over alphabet should be 0, got %f", h)
	}
}

func TestComputeEntropyOverAlphabetNoMatch(t *testing.T) {
	alpha := map[byte]bool{'A': true}
	if h := ComputeEntropyOverAlphabet("bbbb", alpha); h != 0.0 {
		t.Errorf("no matching chars should give 0 entropy, got %f", h)
	}
}

func TestComputeEntropyOverAlphabetBase64(t *testing.T) {
	s := "YWJjZGVmZ2hpamtsbW5vcA=="
	h := ComputeEntropyOverAlphabet(s, base64Alphabet)
	if h < 3.0 {
		t.Errorf("base64 over base64 alphabet should have decent entropy, got %f", h)
	}
}

func TestLog2TableInit(t *testing.T) {
	// Trigger table initialization.
	_ = ComputeEntropy("test")
	// Verify table values are reasonable.
	log2TableOnce.Do(initLog2Table)
	for i := 1; i < 256; i++ {
		if log2Table[i] >= 0 {
			// log2 of values < 1 should be negative — our table stores that.
			// Actually for ratio i/256 where i in [1,255], ratio < 1, so log2 < 0.
			// The precomputed values are negative.
			if log2Table[i] > 0 {
				t.Errorf("log2Table[%d] = %f, expected negative (ratio < 1)", i, log2Table[i])
			}
		}
	}
}

func TestComputeEntropySingleUniqueByte(t *testing.T) {
	// When only one unique byte exists, entropy should be 0.
	h := ComputeEntropy("bbbbbbbbbb")
	if h != 0.0 {
		t.Errorf("single unique byte entropy should be 0, got %f", h)
	}
}

func TestComputeEntropyTwoBytes(t *testing.T) {
	// Two bytes equally distributed.
	h := ComputeEntropy("ab")
	// With 2 unique chars, each appearing once, entropy = -(0.5*log2(0.5) + 0.5*log2(0.5)) = 1.0
	if h < 0.9 || h > 1.1 {
		t.Errorf("two-byte equal distribution entropy should be ~1.0, got %f", h)
	}
}

func TestComputeEntropyOverAlphabetAllMatch(t *testing.T) {
	// All chars in string are in alphabet.
	alpha := map[byte]bool{'A': true, 'B': true, 'C': true}
	h := ComputeEntropyOverAlphabet("ABCABCABC", alpha)
	if h < 0.5 {
		t.Errorf("should have non-zero entropy, got %f", h)
	}
}

func TestComputeEntropyOverAlphabetSingleUniqueInAlphabet(t *testing.T) {
	// Only one unique char from alphabet.
	alpha := map[byte]bool{'A': true}
	h := ComputeEntropyOverAlphabet("AAAA", alpha)
	// Entropy may be non-zero due to floating-point approximation in table.
	// It should be very close to 0.
	if h > 0.01 {
		t.Errorf("single unique char in alphabet should have ~0 entropy, got %f", h)
	}
}
