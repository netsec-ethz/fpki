package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEmptyHash checks that the hash of anything is always something.
func TestEmptyHash(t *testing.T) {
	v := SHA256Hash()
	require.NotEmpty(t, v)

	a := SHA256Hash32Bytes()
	require.Equal(t, v, a[:])
}
