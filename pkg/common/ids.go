package common

import (
	"bytes"
	"sort"
)

// BytesToIDs takes a sequence of bytes and returns a slice of IDs, where the byte sequence
// is a set of N blocks of ID size.
// The function expects the sequence to be the correct length (or panic).
func BytesToIDs(buff []byte) []SHA256Output {
	N := len(buff) / SHA256Size
	IDs := make([]SHA256Output, N)
	for i := 0; i < N; i++ {
		IDs[i] = *(*SHA256Output)(buff[i*SHA256Size : (i+1)*SHA256Size])
	}
	return IDs
}

func IDsToBytes(IDs []SHA256Output) []byte {
	// Glue the sorted IDs.
	gluedIDs := make([]byte, SHA256Size*len(IDs))
	for i, id := range IDs {
		copy(gluedIDs[i*SHA256Size:], id[:])
	}
	return gluedIDs
}

// SortIDsAndGlue takes a sequence of IDs, sorts them alphabetically, and glues every byte of
// them together.
// The IDs are expected to be unique.
func SortIDsAndGlue(IDs []SHA256Output) []byte {
	// Copy slice to avoid mutating of the original.
	ids := append(IDs[:0:0], IDs...)
	// Sort the IDs.
	sort.Slice(ids, func(i, j int) bool {
		return bytes.Compare(ids[i][:], ids[j][:]) == -1
	})
	return IDsToBytes(ids)
}
