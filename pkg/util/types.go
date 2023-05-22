package util

import "fmt"

// ToTypedSlice expects a slice as input and returns a slice whose elements are converted to the
// required type one by one, or error.
func ToTypedSlice[T any](obj any) ([]T, error) {
	s, ok := obj.([]any)
	if !ok {
		return nil, fmt.Errorf("the content is of type %T instead of []any", obj)
	}
	t := make([]T, len(s))
	for i, e := range s {
		if te, ok := e.(T); ok {
			t[i] = te
		} else {
			return nil, fmt.Errorf("element at %d of type %T cannot be converted to %T",
				i, e, *new(T))
		}
	}
	return t, nil
}

// ToType returns the passed object as the specified type, or error.
func ToType[T any](obj any) (T, error) {
	if o, ok := obj.(T); ok {
		return o, nil
	}
	return *new(T), fmt.Errorf("cannot convert from %T into %T", obj, *new(T))
}
