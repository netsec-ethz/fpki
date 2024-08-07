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
// other elements that will not be removed.
// The indices to remove must not repeat, must be inside bounds of the slice,
// but can be unordered.
func RemoveElementsFromSlice[T any](slice *[]T, indices []int) {
	if len(indices) >= len(*slice) {
		*slice = (*slice)[:0]
		return
	}

	// We need to sort the indices.
	indices = Qsort(indices)

	// Starts from the beginning of the slice, picks the first element to remove, finds the end-most
	// element staying, and swap them.
	j := len(indices) - 1 // j starts from the end of the indices.
	i := 0                // i starts from the beginning of the indices.
	// The variable toStay represents the last candidate index that will remain in the slice.
	toStay := len(*slice) - i - len(indices) + j
	for ; i <= j && i < len(*slice)-len(indices); i, toStay = i+1, toStay-1 {
		// Find an element that will not be removed.
		// The variable j decrements as we discard elements.
		for ; j >= i; j, toStay = j-1, toStay-1 {
			// An element stays if there are no indices pointing to it; which is equivalent to
			// find an index that is smaller than that element.
			if indices[j] < toStay {
				break
			}
		}

		// We found an element that will not be removed, swap it with i.
		toDelete := indices[i]
		(*slice)[toDelete] = (*slice)[toStay]
	}
	*slice = (*slice)[:len(*slice)-len(indices)]
}

func ResizeSlice[T any](s *[]T, length int, fillWith T) {
	if cap(*s) < length {
		// Not enough capacity.
		*s = make([]T, length)
	} else if len(*s) < length {
		// Enough capacity, length too small.
		for i := len(*s); i < length; i++ {
			*s = append(*s, fillWith)
		}
	} else {
		// Enough capacity, too much length.
		*s = (*s)[:length]
	}
}
