package util

import (
	"math/rand"

	"golang.org/x/exp/constraints"
)

// Qsort is a quick sort in place in pure Go. Does not allocate.
func Qsort[T constraints.Ordered](a []T) []T {
	if len(a) < 2 {
		return a
	}

	left, right := 0, len(a)-1

	// Pick a pivot
	pivotIndex := rand.Int() % len(a)

	// Move the pivot to the right
	a[pivotIndex], a[right] = a[right], a[pivotIndex]

	// Pile elements smaller than the pivot on the left
	for i := range a {
		if a[i] < a[right] {
			a[i], a[left] = a[left], a[i]
			left++
		}
	}

	// Place the pivot after the last smaller element
	a[left], a[right] = a[right], a[left]

	// Go down the rabbit hole
	Qsort(a[:left])
	Qsort(a[left+1:])

	return a
}
