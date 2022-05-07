package batchedsmt

// one batch represents one sub-tree (4 layers)
// Batch
// ------------------------------------------------
// isShortcut                       1 byte           (whether this sub-tree only contains one leaf)
// all nodes in a sub-tree(30)     [32]byte
// -------------------------------------------------
// parseBatch decodes the byte data into a slice of nodes and bitmap
func (s *SMT) parseBatch(val []byte) [][]byte {
	batch := make([][]byte, 31, 31)
	bitmap := val[:4]
	// if the batch root is a shortcut
	if bitIsSet(val, 31) {
		// batch[0] is a flag to flag the shortcut
		batch[0] = []byte{1}
		batch[1] = val[4 : 4+33]
		batch[2] = val[4+33 : 4+33*2]
	} else {
		batch[0] = []byte{0}
		j := 0
		for i := 1; i <= 30; i++ {
			// only load the node if it is not empty
			if bitIsSet(bitmap, i-1) {
				batch[i] = val[4+33*j : 4+33*(j+1)]
				j++
			}
		}
	}
	return batch
}

// serialise batch to bytes
func serializeBatch(batch [][]byte) []byte {
	serialized := make([]byte, 4)
	if batch[0][0] == 1 {
		// the batch node is a shortcut
		setBit(serialized, 31)
	}
	for i := 1; i < 31; i++ {
		if len(batch[i]) != 0 {
			setBit(serialized, i-1)
			serialized = append(serialized, batch[i]...)
		}
	}
	return serialized
}
