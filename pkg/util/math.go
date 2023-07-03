package util

import "golang.org/x/exp/constraints"

// Pow returns x raised to n.
// Adapted from https://stackoverflow.com/a/71289792/817736
func Pow[X number, N constraints.Unsigned](x X, n N) X {
	if n == 0 {
		return 1
	}
	if n == 1 {
		return x
	}
	y := Pow(x, n/2)
	if n%2 == 0 {
		return y * y
	}
	return x * y * y
}

type number interface {
	constraints.Float | constraints.Integer
}
