package util

import "fmt"

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
