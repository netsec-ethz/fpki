package util_test

import (
	"sort"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestQsort(t *testing.T) {
	cases := map[string]struct {
		slice []int
	}{
		"empty": {
			slice: []int{},
		},
		"consecutive": {
			slice: []int{1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		"reverse": {
			slice: []int{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		},
		"holes": {
			slice: []int{9, 8, 5, 4, 1, 0},
		},
		"updown": {
			slice: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			var got []int
			allocs := tests.AllocsPerRun(func(tests.B) {
				got = util.Qsort(tc.slice)
			})
			require.True(t, sort.IntsAreSorted(got))
			require.Equal(t, 0, allocs)
		})
	}
}
