package pii

import (
	"math"
	"sync"
)

// log2Table provides pre-computed log2 values for possible byte frequency
// ratios. Using a lookup table avoids repeated math.Log2 calls in the hot
// path when computing entropy over many candidates.
//
// Initialized lazily via sync.Once to avoid package-level init() functions
// (per CISO SEC-REQ-09 requirement).
var (
	log2TableOnce sync.Once
	log2Table     [256]float64
)

func initLog2Table() {
	for i := range log2Table {
		if i == 0 {
			log2Table[i] = 0
		} else {
			log2Table[i] = math.Log2(float64(i) / 256.0)
		}
	}
}

// ComputeEntropy calculates the Shannon entropy of a given string.
//
// The entropy H is defined as:
//
//	H = -Σ (count(c) / n) * log₂(count(c) / n)
//
// where the sum is over all unique bytes in the string, count(c) is the
// frequency of byte c, and n is the total length.
//
// The function uses a stack-allocated [256]int frequency counter for O(1)
// space and single-pass O(n) time. It uses a lazily-initialized log2 lookup
// table for performance.
//
// For empty strings, returns 0.0.
// For single-character strings, returns 0.0 (one unique symbol).
func ComputeEntropy(s string) float64 {
	n := len(s)
	if n == 0 {
		return 0.0
	}

	// Stack-allocated frequency counter — no heap allocation.
	var freq [256]int
	for i := 0; i < n; i++ {
		freq[s[i]]++
	}

	// Ensure lookup table is initialized.
	log2TableOnce.Do(initLog2Table)

	// Compute entropy using pre-computed table.
	// Scale: tableIndex ≈ count/n * 256
	// Quick check: if only one unique byte, entropy is exactly 0.
	if len(freq) > 0 && countNonZero(freq[:]) == 1 {
		return 0.0
	}

	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		// (count*256)/n is always < 256 because countNonZero==1 is caught above.
		index := (count * 256) / n
		entropy -= (float64(count) / float64(n)) * log2Table[index]
	}

	return entropy
}

// countNonZero counts the number of non-zero entries in a frequency array.
func countNonZero(freq []int) int {
	count := 0
	for _, f := range freq {
		if f > 0 {
			count++
		}
	}
	return count
}

// ComputeEntropyOverAlphabet calculates Shannon entropy limited to a specific
// character alphabet. Characters not in the alphabet are ignored.
func ComputeEntropyOverAlphabet(s string, alphabet map[byte]bool) float64 {
	if len(s) == 0 {
		return 0.0
	}

	var freq [256]int
	totalInAlphabet := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if alphabet[b] {
			freq[b]++
			totalInAlphabet++
		}
	}

	if totalInAlphabet == 0 {
		return 0.0
	}

	log2TableOnce.Do(initLog2Table)

	var entropy float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		index := (count * 256) / totalInAlphabet
		if index >= 256 {
			index = 255
		}
		entropy -= (float64(count) / float64(totalInAlphabet)) * log2Table[index]
	}

	return entropy
}
