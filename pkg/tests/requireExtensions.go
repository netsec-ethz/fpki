package tests

import (
	"sort"

	"github.com/stretchr/testify/require"
)

// RequireSameDereferencedValues compares the elements of two slices like require.ElementsMatch
// does, but dereferencing the pointers contained in the slices. As such, the order of the
// elements in the slices is not important.
// The function allows for comparison even when the types are not comparable natively, by means of
// the lessFcn function. The lessFcn needs to induce a weak ordering.
func RequireDerefElementsMatch[T any](t require.TestingT, a, b []*T, lessFcn func(*T, *T) bool) {
	x := append(a[:0:0], a...)
	y := append(a[:0:0], a...)

	sort.Slice(x, func(i, j int) bool {
		return lessFcn(x[i], x[j])
	})
	sort.Slice(y, func(i, j int) bool {
		return lessFcn(y[i], x[j])
	})

	require.Equalf(t, x, y, "Sorted slices are not equal.\nOriginal slices:\n"+
		"a: %v\nb: %v\nSorted slices:\na: %v\nb: %v", a, b, x, y)
}
