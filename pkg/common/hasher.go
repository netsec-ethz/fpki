package common

import (
	"hash"
	"unsafe"

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

type Hasher struct {
	hasher  hash.Hash
	storage SHA256Output
}

func NewHasher() *Hasher {
	return &Hasher{
		hasher: sha256.New(),
	}
}

func (h *Hasher) Hash(hashOut *SHA256Output, data []byte) {
	h.hasher.Reset()
	h.hasher.Write(data)
	// Use the `storage` array as storage, but set its size to zero.
	*hashOut = SHA256Output(h.hasher.Sum((*hashOut)[:0]))
}

func (h *Hasher) HashString(hashOut *SHA256Output, str string) {
	bytes := unsafe.Slice(unsafe.StringData(str), len(str))
	h.Hash(hashOut, bytes)
}

func (h *Hasher) HashCopy(data []byte) SHA256Output {
	h.Hash(&(h.storage), data)
	// Returns a copy so that this function can be called several times and not overwrite.
	return h.storage
}

func (h *Hasher) HashStringCopy(str string) SHA256Output {
	h.HashString(&(h.storage), str)
	// Returns a copy so that this function can be called several times and not overwrite.
	return h.storage
}
