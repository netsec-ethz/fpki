package util

// DeduplicateSlice removes all non unique items from the slices.
// The valueFunc should return the (comparable) representation of the item to deduplicate at i.
// If there is only one slice that contains the possibly duplicated elements, use the already
// defined functions WithSlice, if the slice contains values, or WithSlicePtr, if contains pointers.
// The slave slices loose their elements which correspond to those indices where valueFunc
// returned a duplicated item.
// The function does not preserve the order of the slices, but ensures that the correspondence
// between master[i] and slave1[i] is preserved.
func DeduplicateSlice[T comparable](
	valueFunc func(int) T, // The function used to retrieve a comparable value from the slices.
	slices ...sliceLike, // Slices.
) {
	makeUnique[T](valueFunc, slices...)
}

func WithSlice[T comparable](slice []T) func(int) T {
	return func(i int) T {
		return slice[i]
	}
}

func WithSlicePtr[T comparable](slice []*T) func(int) T {
	return func(i int) T {
		return *slice[i]
	}
}

type sWrap[T any] struct {
	Ptr *[]T
}

func Wrap[T any](slice *[]T) sWrap[T] {
	s := sWrap[T]{
		Ptr: slice,
	}
	return s
}

func (s sWrap[T]) Len() int {
	return len(*s.Ptr)
}

func (s sWrap[T]) CopyElem(to, from int) {
	(*s.Ptr)[to] = (*s.Ptr)[from]
}

func (s sWrap[T]) SetSize(newSize int) {
	*s.Ptr = (*s.Ptr)[:newSize]
}

type sliceLike interface {
	Len() int
	CopyElem(to, from int)
	SetSize(int)
}

// makeUnique takes a function returning the comparable element from any slice
// (to be able to check if it was seen already), usually one or more of the slices argument,
// and modifies all these slices so that the getElem function doesn't return duplicates.
// The slices passed as argument loose their elements where a duplicate is found.
// The function does not preserve the original order of the slices.
// E.g. If master = {1,2,3,1}, slave1 = {a,b,c,a}, after calling the function, the new values
// are: master = {1,3,2}, slave1 = {a,c,b}.
// The order of the slices is not preserved, they are treated like a set.
func makeUnique[T comparable](
	getElem func(int) T,
	slices ...sliceLike,
) {
	master := slices[0]
	set := make(map[T]struct{})
	for i := 0; i < master.Len(); i++ {
		e := getElem(i)
		if _, ok := set[e]; !ok {
			// New item, continue.
			set[e] = struct{}{}
			continue
		}

		// Already present at i, pull last item and reduce slice size.
		lastElemIndex := master.Len() - 1 // Index of last element.
		master.CopyElem(i, lastElemIndex) // last item to i
		master.SetSize(lastElemIndex)     // reduce slice size

		// Now the rest of slices, guided by `master`.
		for _, s := range slices[1:] {
			s.CopyElem(i, lastElemIndex) // len(master) was already decreased
		}

		// Loop again but treat this new element, in the existing index.
		i--
	}

	// Adjust size of the other slices.
	newSize := master.Len()
	for _, s := range slices[1:] {
		s.SetSize(newSize)
	}
}
