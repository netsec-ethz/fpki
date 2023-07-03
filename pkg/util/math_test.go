package util

import (
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
