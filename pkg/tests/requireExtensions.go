package tests

import "github.com/stretchr/testify/require"

// RequireSameDereferencedValues compares the elements of two slices like require.ElementsMatch
// does, but dereferencing the pointers contained in the slices.
func RequireDerefElementsMatch[T comparable](t require.TestingT, a, b []*T) {
	if len(a) != len(b) {
		require.FailNowf(t, "elements differ", "different sizes a,b %d != %d", len(a), len(b))
	}
	setA := make(map[T]struct{})
	for _, e := range a {
		setA[*e] = struct{}{}
	}

	setB := make(map[T]struct{})
	for _, e := range b {
		setB[*e] = struct{}{}
	}

	require.Equal(t, setA, setB)
}
