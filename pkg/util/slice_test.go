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
			indices:  []int{2, 0},
			expected: []int{1},
		},
		"head": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{0, 2, 1},
			expected: []int{3, 4, 5},
		},
		"tail": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{3, 2, 5, 4},
			expected: []int{0, 1},
		},
		"interleaved": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{4, 2, 0},
			expected: []int{1, 3, 5},
		},
		"interleaved2": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{1, 5, 3},
			expected: []int{0, 2, 4},
		},
		"all": {
			slice:    []int{0, 1, 2, 3, 4, 5},
			indices:  []int{1, 0, 3, 2, 5, 4},
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

func TestResizeSlice(t *testing.T) {
	cases := map[string]struct {
		nilSlice  bool
		cap       int
		len       int
		requested int
		fillWith  int
	}{
		"noop": {
			cap:       1,
			len:       1,
			requested: 1,
		},
		"zero": {
			cap:       1,
			len:       0,
			requested: 0,
		},
		"reduce": {
			cap:       2,
			len:       2,
			requested: 1,
		},
		"enlarge": {
			cap:       4,
			len:       1,
			requested: 6,
		},
		"empty": {
			cap:       0,
			len:       0,
			requested: 4,
		},
		"filled": {
			requested: 3,
			fillWith:  42,
		},
		"nil": {
			nilSlice:  true,
			requested: 6,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			var s []int
			if !tc.nilSlice {
				s = make([]int, tc.len, tc.cap)
			}
			origAddr := (*[0]int)(s)
			t.Logf("ini addr = %p", origAddr)

			util.ResizeSlice(&s, tc.requested, tc.fillWith)
			require.Equal(t, tc.requested, len(s))

			gotAddr := (*[0]int)(s)
			t.Logf("got addr = %p", gotAddr)
			t.Logf("equal? %v", origAddr == gotAddr)

			if tc.cap >= tc.requested {
				// Expect reusing the storage.
				require.True(t, origAddr == gotAddr)
			} else {
				// Expect storage to be different.
				require.False(t, origAddr == gotAddr)
				// Expect new values to be filled.
				for i, v := range s[tc.len:] {
					require.Equal(t, tc.fillWith, v, "at index %d", i+tc.len)
				}
			}
		})
	}
}
