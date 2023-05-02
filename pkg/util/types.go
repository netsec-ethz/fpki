package util

import "fmt"

func ToTypedSlice[T any](s []any) ([]T, error) {
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
