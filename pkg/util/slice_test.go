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
