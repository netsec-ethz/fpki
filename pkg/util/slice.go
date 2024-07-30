package util

// RemoveElemFromSlice removes the index-th element from the slice, by moving the last element of
// the slice to that position, and decreasing the size.
// Thus the function does not preserve ordering.
func RemoveElemFromSlice[T any](slice *[]T, index int) {
	N := len(*slice) - 1
	(*slice)[index] = (*slice)[N]
	*slice = (*slice)[:N]
}
