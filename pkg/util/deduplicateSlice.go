package util

// DeduplicateNonPointer removes all non unique items from the master slice.
// The master slice contains comparable values, not pointers to values.
// The slave slices loose their elements which correspond to those indices lost in master.
// The function does not preserve the order of the slices, but ensures that the correspondence
// between master[i] and slave1[i] is preserved.
func DeduplicateNonPointer[T comparable](masterSlice sWrap[T], slaveSlices ...sliceLike) {
	makeUnique[T, T](func(t []T, i int) T {
		return (*masterSlice.Ptr)[i]
	}, masterSlice, slaveSlices...)
}

// DeduplicatePointer removes all non unique items from the master slice.
// The master slice contains pointers to comparable values.
// The slave slices loose their elements which correspond to those indices lost in master.
// The function does not preserve the order of the slices, but ensures that the correspondence
// between master[i] and slave1[i] is preserved.
func DeduplicatePointer[T comparable](masterSlice sWrap[*T], slaveSlices ...sliceLike) {
	makeUnique[*T, T](func(t []*T, i int) T {
		return *(*masterSlice.Ptr)[i]
	}, masterSlice, slaveSlices...)
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

func (s sWrap[T]) CopyElem(to, from int) {
	(*s.Ptr)[to] = (*s.Ptr)[from]
}

func (s sWrap[T]) SetSize(newSize int) {
	*s.Ptr = (*s.Ptr)[:newSize]
}

type sliceLike interface {
	CopyElem(to, from int)
	SetSize(int)
}

// makeUnique takes a function returning the comparable element from the master slice
// (to be able to check if it was seen already), the master slice (the slice where we check
// for already present elements), and slave slices, and modifies all these slices so that
// the master slice contains unique elements (according to the getElem function), and the
// slave slices contain the corresponding items to the indices in the master slice.
// E.g. If master = {1,2,3,1}, slave1 = {a,b,c,a}, after calling the function, the new values
// are: master = {1,3,2}, slave1 = {a,c,b}.
// The order of the slices is not preserved, they are treated like a set.
func makeUnique[T any, V comparable](
	getElem func([]T, int) V,
	master sWrap[T],
	slaves ...sliceLike,
) {
	set := make(map[V]struct{})
	for i := 0; i < len(*master.Ptr); i++ {
		e := getElem(*master.Ptr, i)
		if _, ok := set[e]; !ok {
			// New item, continue.
			set[e] = struct{}{}
			continue
		}
		// Already present at i, pull last item and reduce slice size.
		lastIndex := len(*master.Ptr) - 1
		master.CopyElem(i, lastIndex) // last item to i
		master.SetSize(lastIndex)     // reduce slice size

		// Now the rest of slices, guided by `master`.
		for _, s := range slaves {
			s.CopyElem(i, lastIndex) // len(master) was already decreased
		}

		// Loop again but treat this new element, in the existing index.
		i--
	}

	// Adjust size of the other slices.
	newSize := len(*master.Ptr)
	for _, s := range slaves {
		s.SetSize(newSize)
	}
}
