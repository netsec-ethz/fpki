package util

import (
	"math/rand"

	"github.com/stretchr/testify/require"
)

func RandomBytesForTest(t require.TestingT, size int) []byte {
	buff := make([]byte, size)
	n, err := rand.Read(buff)
	require.NoError(t, err)
	require.Equal(t, size, n)
	return buff
}
