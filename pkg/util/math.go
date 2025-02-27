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

// Log2 computes ceil(log2(N)). It is analogous to the order of the MSB of N-1,
// E.g. N=9, N-1=8 in decimal, 1000 in binary, Log2=4.
// With N=16, N-1=15, 1111 in binary, Log2=4.
func Log2(N uint) uint {
	if N == 0 {
		return 0
	}
	nBits := uint(0)
	for n := N - 1; n > 0; n >>= 1 {
		nBits++
	}
	return nBits
}

type number interface {
	constraints.Float | constraints.Integer
}
