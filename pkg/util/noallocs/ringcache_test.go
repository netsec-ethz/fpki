package noallocs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRingCache(t *testing.T) {
	rc := NewRingCache(3, WithPerNewElement(func(t *[]byte) {
		*t = make([]byte, 2)
		(*t)[0] = 4
		(*t)[1] = 2
	}))

	require.Equal(t, 3, len(rc.elements))
	for i := range 3 {
		require.Equal(t, 2, len(rc.elements[i]))
		require.Equal(t, byte(4), rc.elements[i][0])
		require.Equal(t, byte(2), rc.elements[i][1])
	}
}

func TestRingCacheCurrent(t *testing.T) {
	rc := NewRingCache(2, WithPerNewElement(func(t *[]byte) {
		*t = make([]byte, 2)
	}))

	{
		curr := rc.Current()
		curr[0] = 1
		curr[1] = 2

		rc.Next()
		curr = rc.Current()
		curr[0] = 11
		curr[1] = 12
	}

	rc.Next()
	require.Equal(t, byte(1), rc.elements[0][0])
	require.Equal(t, byte(2), rc.elements[0][1])

	rc.Next()
	require.Equal(t, byte(11), rc.elements[1][0])
	require.Equal(t, byte(12), rc.elements[1][1])
}
