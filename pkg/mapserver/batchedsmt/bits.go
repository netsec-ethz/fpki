package batchedsmt

// ------------------------------------------------
//             bit related operations
// ------------------------------------------------
// bitIsSet: check one bit to high
func bitIsSet(bits []byte, i int) bool {
	return bits[i/8]&(1<<uint(7-i%8)) != 0
}

// setBit: set one bit to high
func setBit(bits []byte, i int) {
	bits[i/8] |= 1 << uint(7-i%8)
}
