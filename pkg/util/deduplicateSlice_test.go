package util_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func TestDeduplicate(t *testing.T) {
	t.Run("value1", func(t *testing.T) {
		a := []int{
			1,
			2,
			3,
			1,
		}
		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlice(a),
				util.Wrap(&a),
			)
		})

		require.Equal(t, 3, len(a))

		// Since the functions to make unique don't necessarily preserve the order, we check
		// equality using ElementsMatch.
		require.ElementsMatch(t, []int{1, 2, 3}, a)

		require.Equal(t, 0, allocs)
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

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlice(a),
				util.Wrap(&a),
				util.Wrap(&b),
				util.Wrap(&c),
			)
		})

		expectedSize := 2
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []int{1, 2}, a)
		require.ElementsMatch(t, []int{11, 22}, b)
		require.ElementsMatch(t, []*int{ptr(0), ptr(1)}, c)

		require.Equal(t, 0, allocs)
	})

	t.Run("valueStruct1", func(t *testing.T) {
		a := []myType{
			{1},
			{1},
			{2},
		}

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlice(a),
				util.Wrap(&a),
			)
		})

		require.Equal(t, 2, len(a))

		require.ElementsMatch(t, []myType{{1}, {2}}, a)

		require.Equal(t, 0, allocs)
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

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlice(a),
				util.Wrap(&a),
				util.Wrap(&b),
			)
		})

		expectedSize := 2
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))

		require.ElementsMatch(t, []myType{{1}, {2}}, a)
		require.ElementsMatch(t, []int{0, 2}, b)

		require.Equal(t, 0, allocs)
	})

	t.Run("valueStruct3", func(t *testing.T) {
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

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlice(a),
				util.Wrap(&a),
				util.Wrap(&b),
				util.Wrap(&c),
			)
		})

		expectedSize := 5
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []myType{{1}, {2}, {3}, {4}, {5}}, a)
		require.ElementsMatch(t, []int{11, 22, 33, 44, 55}, b)
		require.ElementsMatch(t, []*int{ptr(0), ptr(1), ptr(2), ptr(3), ptr(4)}, c)

		require.Equal(t, 0, allocs)
	})

	t.Run("valueStruct4", func(t *testing.T) {
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

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlice(a),
				util.Wrap(&a),
				util.Wrap(&b),
				util.Wrap(&c),
			)
		})

		expectedSize := 3
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []myType{{1}, {2}, {3}}, a)
		require.ElementsMatch(t, []int{11, 22, 33}, b)
		require.ElementsMatch(t, []*myType{ptr(myType{11}), ptr(myType{22}), ptr(myType{33})}, c)

		require.Equal(t, 0, allocs)
	})

	t.Run("pointer1", func(t *testing.T) {
		a := []*int{
			ptr(1),
			ptr(1),
			ptr(3),
			ptr(3),
		}

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlicePtr(a),
				util.Wrap(&a),
			)
		})

		require.Equal(t, 2, len(a))

		require.ElementsMatch(t, []*int{ptr(1), ptr(3)}, a)

		require.Equal(t, 0, allocs)
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

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlicePtr(a),
				util.Wrap(&a),
				util.Wrap(&b),
			)
		})

		require.Equal(t, 2, len(a))
		require.Equal(t, 2, len(b))

		require.ElementsMatch(t, []*int{ptr(1), ptr(3)}, a)
		require.ElementsMatch(t, []int{0, 2}, b)

		require.Equal(t, 0, allocs)
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

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlicePtr(a),
				util.Wrap(&a),
				util.Wrap(&b),
				util.Wrap(&c),
			)
		})

		expectedSize := 4
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []*myArray{ptr(id1), ptr(id2), ptr(id3), ptr(id4)}, a)
		require.ElementsMatch(t, []int{11, 22, 33, 44}, b)
		tests.RequireDerefElementsMatch(t, []*myType{
			ptr(myType{1}), ptr(myType{2}), ptr(myType{3}), ptr(myType{4})},
			c,
			func(x, y *myType) bool { return x.Count < y.Count },
		)

		require.Equal(t, 0, allocs)
	})

	t.Run("complex1", func(t *testing.T) {
		// Two "dimensions": similar to updater.Certificates domain and cert ID.
		// Dim1,	Dim2:
		// 1, 		1
		// 1, 		2
		// 2, 		1
		// 2, 		2

		a := []*certificate{
			ptr(newCert(1, 1, "11")),
			ptr(newCert(1, 2, "12")),
			ptr(newCert(2, 2, "22")), // dup
			ptr(newCert(1, 1, "11")), // dup
			ptr(newCert(2, 1, "21")),
			ptr(newCert(2, 2, "22")),
			ptr(newCert(1, 2, "12")), // dup
			ptr(newCert(2, 1, "21")), // dup
		}
		b := []int{
			11,
			12,
			22, // dup
			11, // dup
			21,
			22,
			12, // dup
			21, // dup
		}

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				func(i int) [2]int {
					return [2]int{
						*a[i].Domain,
						*a[i].Cert,
					}
				},
				util.Wrap(&a),
				util.Wrap(&b),
			)
		})

		expectedSize := 4
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))

		tests.RequireDerefElementsMatch(t,
			[]*certificate{
				ptr(newCert(1, 1, "11")),
				ptr(newCert(1, 2, "12")),
				ptr(newCert(2, 1, "21")),
				ptr(newCert(2, 2, "22")),
			},
			a,
			func(c1, c2 *certificate) bool {
				return *c1.Domain < *c2.Domain &&
					*c1.Cert < *c2.Cert &&
					c1.Names[0] < c2.Names[0]
			},
		)
		require.ElementsMatch(t, []int{11, 12, 21, 22}, b)

		require.Equal(t, 0, allocs)
	})

	t.Run("complex2", func(t *testing.T) {
		// The uniqueness is determined from a AND b.
		// Elements:
		// 1,1, ...
		// 1,2, ...
		// 1,1, ...  // dup
		// 2,1, ...
		// 2,2, ...
		// 2,2, ...  // dup
		// 1,1, ...  // dup
		a := []*int{
			ptr(1),
			ptr(1),
			ptr(1),
			ptr(2),
			ptr(2),
			ptr(2),
			ptr(1),
		}
		b := []*int{
			ptr(1),
			ptr(2),
			ptr(1),
			ptr(1),
			ptr(2),
			ptr(2),
			ptr(1),
		}
		c := []string{
			"1,1",
			"1,2",
			"1,1",
			"2,1",
			"2,2",
			"2,2",
			"1,1",
		}

		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				func(i int) [2]int {
					return [2]int{
						*a[i],
						*b[i],
					}
				},
				util.Wrap(&a),
				util.Wrap(&b),
				util.Wrap(&c),
			)
		})

		expectedSize := 4
		require.Equal(t, expectedSize, len(a))
		require.Equal(t, expectedSize, len(b))
		require.Equal(t, expectedSize, len(c))

		require.ElementsMatch(t, []*int{ptr(1), ptr(1), ptr(2), ptr(2)}, a)
		require.ElementsMatch(t, []*int{ptr(1), ptr(1), ptr(2), ptr(2)}, b)
		require.ElementsMatch(t, []string{"1,1", "1,2", "2,1", "2,2"}, c)

		require.Equal(t, 0, allocs)
	})
}

func TestAllocs(t *testing.T) {
	t.Run("maps", func(t *testing.T) {
		a := make([]int, 1000)
		clear(a)
		allocs := tests.AllocsPerRun(func() {
			for i := range a {
				a[i] = i
			}
		})
		require.Equal(t, 0, allocs)

		clear(a)
		allocs = tests.AllocsPerRun(func() {
			for i := range a {
				a[i] = i
			}
		})
		require.Equal(t, 0, allocs)
	})
	t.Run("without", func(t *testing.T) {
		// Without storage.
		a := make([]int, 1000)
		for i := range a {
			a[i] = i
		}
		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSlice(
				util.WithSlice(a),
				util.Wrap(&a),
			)
		})

		require.Greater(t, allocs, 0)
	})
	t.Run("own_storage", func(t *testing.T) {
		// With storage.
		cap := 2000
		len_ := 1000
		a := make([]int, len_)
		for i := range a {
			a[i] = i
		}
		storage := make(map[int]struct{}, cap)
		allocs := tests.AllocsPerRun(func() {
			util.DeduplicateSliceWithStorage(
				storage,
				util.WithSlice(a),
				util.Wrap(&a),
			)
		})

		require.Equal(t, 0, allocs)
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

type certificate struct {
	Domain *int
	Cert   *int
	Names  []string
}

func newCert(domain, cert int, names ...string) certificate {
	return certificate{
		Domain: &domain,
		Cert:   &cert,
		Names:  names,
	}
}
