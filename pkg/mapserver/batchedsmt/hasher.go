package batchedsmt

import "crypto/sha256"

// Hasher: SHA256 hash func
func Hasher(data ...[]byte) []byte {
	hasher := sha256.New()
	for i := 0; i < len(data); i++ {
		hasher.Write(data[i])
	}
	return hasher.Sum(nil)
}
