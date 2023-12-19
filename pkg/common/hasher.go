package common

import (
	sha256 "github.com/minio/sha256-simd"
)

const SHA256Size = 32

type SHA256Output [SHA256Size]byte

func SHA256Hash(data ...[]byte) []byte {
	hash := sha256.New()
	for i := 0; i < len(data); i++ {
		hash.Write(data[i])
	}
	return hash.Sum(nil)
}

func SHA256Hash32Bytes(data ...[]byte) SHA256Output {
	output := SHA256Hash(data...) // will never be empty, will always be 32 bytes.
	ptr := (*SHA256Output)(output)
	return *ptr
}
