package util_test

import (
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestRemoveElemFromSlice(t *testing.T) {
	slice := []int{0, 1, 2, 3, 4, 5, 6}
	util.RemoveElemFromSlice(&slice, 6)
	require.ElementsMatch(t, slice, []int{0, 1, 2, 3, 4, 5})

	allocs := tests.AllocsPerRun(func() {
		util.RemoveElemFromSlice(&slice, 2)
	})
	require.ElementsMatch(t, slice, []int{0, 1, 3, 4, 5})
	require.Equal(t, 0, allocs)
}

func TestRemoveElementsFromSlice(t *testing.T) {
	testCases := map[string]struct {
		slice    []int
		indices  []int
		expected []int
	}{
		"empty": {
			slice:    []int{},
			expected: []int{},
		},
		"single": {
			slice:    []int{0, 1, 2},
			indices:  []int{1},
			expected: []int{0, 2},
		},
		"none": {
			slice:    []int{0, 1, 2},
			indices:  []int{},
			expected: []int{0, 1, 2},
		},
		"head-tail": {
			slice:    []int{0, 1, 2},
			indices:  []int{0, 2},
			expected: []int{1},
		},
		"head": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{0, 1, 2},
			expected: []int{3, 4, 5},
		},
		"tail": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{2, 3, 4, 5},
			expected: []int{0, 1},
		},
		"interleaved": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{0, 2, 4},
			expected: []int{1, 3, 5},
		},
		"interleaved2": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{1, 3, 5},
			expected: []int{0, 2, 4},
		},
		"all": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{0, 1, 2, 3, 4, 5},
			expected: []int{},
		},
		"hole": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{0, 1, 4, 5},
			expected: []int{2, 3},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			// XXX: Do not run in parallel.

			allocs := tests.AllocsPerRun(func() {
				util.RemoveElementsFromSlice(&tc.slice, tc.indices)
			})
			require.ElementsMatch(t, tc.slice, tc.expected)
			require.Equal(t, 0, allocs)
		})
	}
}
