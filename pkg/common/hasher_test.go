package common

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEmptyHash checks that the hash of anything is always something.
func TestEmptyHash(t *testing.T) {
	v := SHA256Hash()
	fmt.Printf("Hash of nothing is: %s\n", hex.EncodeToString(v))
	require.NotEmpty(t, v)

	a := SHA256Hash32Bytes()
	require.Equal(t, v, a[:])
}

func TestBytesToIDSequenceAndBack(t *testing.T) {
	sequence := newSequence()
	// sequence is 0,1,...,63
	t.Logf("sequence is %s", hex.EncodeToString(sequence))
	require.Less(t, len(sequence), 256)

	IDs := BytesToIDs(sequence)
	require.Len(t, IDs, 2)

	// Check values of the IDs are sequential.
	checkSequentialValues(t, IDs)

	// Remove the values in the sequence. Underlying memory support should not affect the IDs.
	for i := range sequence {
		sequence[i] = 0xff
	}
	checkSequentialValues(t, IDs)

	// Check that the back conversion works.
	sequence = IDsToBytes(IDs)
	require.Equal(t, newSequence(), sequence)
	// Modify the values of the IDs, the sequence must remain unaltered.
	for _, id := range IDs {
		for i := range id {
			id[i] = 0xAA
		}
	}
	require.Equal(t, newSequence(), sequence)
}

func checkSequentialValues(t require.TestingT, IDs []*SHA256Output) {
	i := 0
	for _, id := range IDs {
		for _, j := range id {
			require.Equal(t, i, int(j))
			i++
		}
	}
}

func newSequence() []byte {
	sequence := make([]byte, 2*SHA256Size)
	for i := range sequence {
		sequence[i] = byte(i)
	}
	return sequence
}
