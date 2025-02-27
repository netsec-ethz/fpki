package util

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPow(t *testing.T) {
	cases := map[string]struct {
		base     int
		exp      uint
		expected int
	}{
		"simple": {
			base:     10,
			exp:      6,
			expected: 1_000_000,
		},
		"odd_power": {
			base:     10,
			exp:      5,
			expected: 100_000,
		},
		"negative_even": {
			base:     -10,
			exp:      4,
			expected: 10_000,
		},
		"negative_odd": {
			base:     -10,
			exp:      5,
			expected: -100_000,
		},
		"62bits": {
			base:     2,
			exp:      62,
			expected: 4611686018427387904,
		},
		"overflow": {
			// This case shows that the Pow function does not work with arbitrary precission numbers
			base:     2,
			exp:      63,
			expected: -9_223_372_036_854_775_808,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := Pow(tc.base, tc.exp)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestLog2(t *testing.T) {
	testCases := map[uint]uint{
		0: 0,
		1: 0,
		2: 1,
		4: 2,
		8: 3,
	}

	// Populate cases automatically from 1 to 1024.
	for i := uint(1); i <= 1024; i++ {
		got := uint(math.Ceil(math.Log2(float64(i))))
		if _, ok := testCases[i]; !ok {
			testCases[i] = got
		}
	}

	for i := uint(1024 * 16); i < 1024*1024; i += 1024 * 13 {
		got := uint(math.Ceil(math.Log2(float64(i))))
		testCases[i] = got
	}

	for N, expected := range testCases {
		N, expected := N, expected
		t.Run(strconv.FormatUint(uint64(N), 10), func(t *testing.T) {
			t.Parallel()
			got := Log2(N)
			require.Equal(t, expected, got, "got: %d expected: %d", int(got), int(expected))
		})
	}
}
