package util_test

import (
	"math/rand"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestDeduplicate(t *testing.T) {
	t.Run("value1", func(t *testing.T) {
		a := []int{
			1,
			2,
			1,
			2,
		}
		b := []int{
			11,
			22,
			11,
			22,
		}
		c := []*int{
			ptr(0),
			ptr(1),
			ptr(0),
			ptr(1),
		}

		util.DeduplicateNonPointer(util.Wrap(&a), util.Wrap(&b), util.Wrap(&c))

		expectedSize := 2
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []int{1, 2}, a)
		require.ElementsMatch(t, []int{11, 22}, b)
		require.ElementsMatch(t, []*int{ptr(0), ptr(1)}, c)
	})

	t.Run("valueStruct1", func(t *testing.T) {
		a := []myType{
			{1},
			{1},
			{2},
			{3},
			{1},
			{3},
			{1},
		}
		b := []int{
			11,
			11,
			22,
			33,
			11,
			33,
			11,
		}
		c := []*myType{
			ptr(myType{11}),
			ptr(myType{11}),
			ptr(myType{22}),
			ptr(myType{33}),
			ptr(myType{11}),
			ptr(myType{33}),
			ptr(myType{11}),
		}
		util.DeduplicateNonPointer(util.Wrap(&a), util.Wrap(&b), util.Wrap(&c))

		expectedSize := 3
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []myType{{1}, {2}, {3}}, a)
		require.ElementsMatch(t, []int{11, 22, 33}, b)
		require.ElementsMatch(t, []*myType{ptr(myType{11}), ptr(myType{22}), ptr(myType{33})}, c)
	})

	//
	//
	//

	t.Run("value1", func(t *testing.T) {
		a := []int{
			1,
			2,
			3,
			1,
		}
		util.DeduplicateNonPointer(util.Wrap(&a))

		require.Equal(t, 3, len(a))

		// Since the functions to make unique don't necessarily preserve the order, we check
		// equality using ElementsMatch.
		require.ElementsMatch(t, []int{1, 2, 3}, a)
	})

	t.Run("value2", func(t *testing.T) {
		a := []int{
			1,
			2,
			2,
			1,
		}
		b := []int{
			11,
			22,
			22,
			11,
		}
		c := []*int{
			ptr(0),
			ptr(1),
			ptr(1),
			ptr(0),
		}
		util.DeduplicateNonPointer(util.Wrap(&a), util.Wrap(&b), util.Wrap(&c))

		expectedSize := 2
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []int{1, 2}, a)
		require.ElementsMatch(t, []int{11, 22}, b)
		require.ElementsMatch(t, []*int{ptr(0), ptr(1)}, c)
	})

	t.Run("valueStruct1", func(t *testing.T) {
		a := []myType{
			{1},
			{1},
			{2},
		}
		util.DeduplicateNonPointer(util.Wrap(&a))

		require.Equal(t, 2, len(a))

		require.ElementsMatch(t, []myType{{1}, {2}}, a)
	})
	t.Run("valueStruct2", func(t *testing.T) {
		a := []myType{
			{1},
			{1},
			{2},
		}
		b := []int{
			0,
			1,
			2,
		}
		util.DeduplicateNonPointer(util.Wrap(&a), util.Wrap(&b))

		expectedSize := 2
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))

		require.ElementsMatch(t, []myType{{1}, {2}}, a)
		require.ElementsMatch(t, []int{0, 2}, b)
	})

	t.Run("valueStruct2", func(t *testing.T) {
		a := []myType{
			{1},
			{1},
			{2},
			{3},
			{3},
			{4},
			{5},
		}
		b := []int{
			11,
			11,
			22,
			33,
			33,
			44,
			55,
		}
		c := []*int{
			ptr(0),
			ptr(0),
			ptr(1),
			ptr(2),
			ptr(2),
			ptr(3),
			ptr(4),
		}
		util.DeduplicateNonPointer(util.Wrap(&a), util.Wrap(&b), util.Wrap(&c))

		expectedSize := 5
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []myType{{1}, {2}, {3}, {4}, {5}}, a)
		require.ElementsMatch(t, []int{11, 22, 33, 44, 55}, b)
		require.ElementsMatch(t, []*int{ptr(0), ptr(1), ptr(2), ptr(3), ptr(4)}, c)
	})

	t.Run("valueStruct3", func(t *testing.T) {
		a := []myType{
			{1},
			{1},
			{2},
			{3},
			{1},
			{3},
			{1},
		}
		b := []int{
			11,
			11,
			22,
			33,
			11,
			33,
			11,
		}
		c := []*myType{
			ptr(myType{11}),
			ptr(myType{11}),
			ptr(myType{22}),
			ptr(myType{33}),
			ptr(myType{11}),
			ptr(myType{33}),
			ptr(myType{11}),
		}
		util.DeduplicateNonPointer(util.Wrap(&a), util.Wrap(&b), util.Wrap(&c))

		expectedSize := 3
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []myType{{1}, {2}, {3}}, a)
		require.ElementsMatch(t, []int{11, 22, 33}, b)
		require.ElementsMatch(t, []*myType{ptr(myType{11}), ptr(myType{22}), ptr(myType{33})}, c)
	})

	t.Run("pointer1", func(t *testing.T) {
		a := []*int{
			ptr(1),
			ptr(1),
			ptr(3),
			ptr(3),
		}
		util.DeduplicatePointer(util.Wrap(&a))

		require.Equal(t, 2, len(a))

		require.ElementsMatch(t, []*int{ptr(1), ptr(3)}, a)
	})

	t.Run("pointer2", func(t *testing.T) {
		a := []*int{
			ptr(1),
			ptr(1),
			ptr(3),
			ptr(3),
			ptr(1),
			ptr(1),
			ptr(1),
		}
		b := []int{
			0,
			0,
			2,
			2,
			0,
			0,
			0,
		}
		util.DeduplicatePointer(util.Wrap(&a), util.Wrap(&b))

		require.Equal(t, 2, len(a))
		require.Equal(t, 2, len(b))

		require.ElementsMatch(t, []*int{ptr(1), ptr(3)}, a)
		require.ElementsMatch(t, []int{0, 2}, b)
	})

	t.Run("ids1", func(t *testing.T) {
		id1 := randomMyArray(t)
		id2 := randomMyArray(t)
		id3 := randomMyArray(t)
		id4 := randomMyArray(t)
		a := []*myArray{
			ptr(id1),
			ptr(id2),
			ptr(id2), // dup
			ptr(id3),
			ptr(id1), // dup
			ptr(id2), // dup
			ptr(id4),
			ptr(id3), // dup
			ptr(id2), // dup
			ptr(id1), // dup
		}
		b := []int{
			11,
			22,
			22,
			33,
			11,
			22,
			44,
			33,
			22,
			11,
		}
		c := []*myType{
			ptr(myType{1}),
			ptr(myType{2}),
			ptr(myType{2}),
			ptr(myType{3}),
			ptr(myType{1}),
			ptr(myType{2}),
			ptr(myType{4}),
			ptr(myType{3}),
			ptr(myType{2}),
			ptr(myType{1}),
		}
		util.DeduplicatePointer(util.Wrap(&a), util.Wrap(&b), util.Wrap(&c))

		expectedSize := 4
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []*myArray{ptr(id1), ptr(id2), ptr(id3), ptr(id4)}, a)
		require.ElementsMatch(t, []int{11, 22, 33, 44}, b)
		tests.RequireDerefElementsMatch(t, []*myType{
			ptr(myType{1}), ptr(myType{2}), ptr(myType{3}), ptr(myType{4})}, c)
	})
}

func ptr[T any](v T) *T {
	return &v
}

type myType struct {
	Count int
}

type myArray [32]byte

func randomMyArray(t *testing.T) myArray {
	buff := make([]byte, 32)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, 32, n)
	return myArray(buff)
}
