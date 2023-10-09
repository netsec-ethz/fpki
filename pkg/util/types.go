package util

import "fmt"

// ToType returns the passed object as the specified type, or error.
func ToType[T any](obj any) (T, error) {
	if o, ok := obj.(T); ok {
		return o, nil
	}
	return *new(T), fmt.Errorf("cannot convert from %T into %T", obj, *new(T))
}

// ToTypedSlice expects a slice (or error is returned). It returs a slice containing all elements
// of the slice converted to the requested type. If not all elements were convertible, an error is
// returned.
func ToTypedSlice[T any](obj any) ([]T, error) {
	s, err := ToType[[]any](obj)
	if err != nil {
		return nil, err
	}
	t, a := SliceToTypedSlice[T](s)
	if len(a) > 0 {
		return nil, fmt.Errorf("not all elements were convertible to %T. At least one of %T is found",
			*new(T), a[0])
	}
	return t, nil
}

// ToTypedSlice expects a slice as input and returns a slice whose elements are converted to the
// required type one by one, and another slice with the remaining elements that couldn't be
// converted.
func SliceToTypedSlice[T any](s []any) ([]T, []any) {
	filtered := make([]T, 0, len(s))
	remaining := make([]any, 0, len(s))
	for _, e := range s {
		if te, ok := e.(T); ok {
			filtered = append(filtered, te)
		} else {
			remaining = append(remaining, e)
		}
	}
	return filtered, remaining
}
