package util

// RemoveElemFromSlice removes the index-th element from the slice, by moving the last element of
// the slice to that position, and decreasing the size.
// Thus the function does not preserve ordering.
func RemoveElemFromSlice[T any](slice *[]T, index int) {
	N := len(*slice) - 1
	(*slice)[index] = (*slice)[N]
	*slice = (*slice)[:N]
}

// RemoveElementsFromSlice removes the elements at indices' positions by replacing them with
// other elements that will not be removed. For that purpose, every time we find a new index
// to be moved, we have to find the corresponding index that will stay, starting from the end
// of the slice.
// The indices to remove must not repeat, must be inside bounds of the slice,
// and in increasing order.
func RemoveElementsFromSlice[T any](slice *[]T, indices []int) {
	if len(indices) >= len(*slice) {
		*slice = (*slice)[:0]
		return
	}

	// This is the boundary starting from the end and moving to the beginning of the slice,
	// that separates data to be removed [0,1,... N,...] from N+1 to end.
	N := len(*slice) - 1

	// Start from the beginning of the slice, pick the first element to remove, find the end-most
	// element staying, and swap them.
	j := len(indices) - 1 // j starts from the end of the indices.
	i := 0
	for ; i <= j && i < len(*slice)-len(indices); i++ { // i starts from the beginning of the indices.
		// Find an element that will not be removed.
		for ; j >= i; j-- {
			// An element stays if there are no indices pointing to it; which is equivalent to
			// find an index that is smaller than that element.
			if indices[j] < N-i {
				break
			} else {
				N--
			}
		}
		// We found an element that will not be removed, swap it with N-i.
		toStay := N - i
		toDelete := indices[i]
		(*slice)[toDelete] = (*slice)[toStay]
	}
	*slice = (*slice)[:len(*slice)-len(indices)]
}
