package common

import sha256 "github.com/minio/sha256-simd"

type SHA256Output [32]byte

// Hash exports default hash function for trie
var SHA256Hash = func(data ...[]byte) []byte {
	hash := sha256.New()
	for i := 0; i < len(data); i++ {
		hash.Write(data[i])
	}
	return hash.Sum(nil)
}

// Hash exports default hash function for trie
var SHA256Hash32Bytes = func(data ...[]byte) SHA256Output {
	hash := sha256.New()
	for i := 0; i < len(data); i++ {
		hash.Write(data[i])
	}
	output := hash.Sum(nil)

	var output32Bytes SHA256Output
	copy(output32Bytes[:], output)

	return output32Bytes
}
