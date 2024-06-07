package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/tests"
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

func TestHasher(t *testing.T) {
	// Prepare test data and expected results.
	data := [2][]byte{
		randomBytes(t, 300),
		randomBytes(t, 301),
	}
	expected := [2][]byte{
		doSha256(data[0]),
		doSha256(data[1]),
	}
	var results [2]SHA256Output

	h := NewHasher()
	var storage SHA256Output

	// Test the hasher.
	h.Hash(&storage, data[0])
	results[0] = storage
	require.Equal(t, expected[0], results[0][:])

	// Again, to check that storage is not overwritten and previous value is still valid.
	h.Hash(&storage, data[1])
	results[1] = storage
	require.Equal(t, expected[1], results[1][:])
	require.Equal(t, expected[0], results[0][:])
}

func TestHasherCopy(t *testing.T) {
	// Prepare test data and expected results.
	data := [2][]byte{
		randomBytes(t, 300),
		randomBytes(t, 301),
	}
	expected := [2][]byte{
		doSha256(data[0]),
		doSha256(data[1]),
	}
	var results [2]SHA256Output

	// Test the hasher.
	h := NewHasher()
	results[0] = h.HashCopy(data[0])
	require.Equal(t, expected[0], results[0][:])

	// Again, to check that storage is not overwritten and previous value is still valid.
	results[1] = h.HashCopy(data[1])
	require.Equal(t, expected[1], results[1][:])
	require.Equal(t, expected[0], results[0][:])
}

func TestHasherAllocations(t *testing.T) {
	// Prepare test data.
	data := randomBytes(t, 1_000_000)

	// Prepare the call to measure.
	var ownStorage SHA256Output
	h := NewHasher()

	// Check allocations when we hash.
	allocs := testing.AllocsPerRun(100, func() {
		h.Hash(&ownStorage, data)
	})

	require.Equal(t, 0.0, allocs)
}

func BenchmarkHashFunction(b *testing.B) {
	b.ReportAllocs()
	data := randomBytes(b, 4096) // 4K data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SHA256Hash32Bytes(data)
	}
}

func BenchmarkHasher(b *testing.B) {
	b.ReportAllocs()
	data := randomBytes(b, 4096) // 4K data
	h := NewHasher()
	var storage SHA256Output

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Hash(&storage, data)
	}
}

func BenchmarkHasherCopy(b *testing.B) {
	b.ReportAllocs()
	data := randomBytes(b, 4096) // 4K data
	h := NewHasher()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.HashCopy(data)
	}
}

func doSha256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

func checkSequentialValues(t require.TestingT, IDs []SHA256Output) {
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

func randomBytes(t tests.T, size int) []byte {
	// TODO: reuse random.RandomBytesForTest. Needs refactoring of the util package into
	// independent-from-data-structures part and dependent-on-common-package.
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}
