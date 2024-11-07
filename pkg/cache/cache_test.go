package cache

import (
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/stretchr/testify/require"
)

func TestHashicorpLru(t *testing.T) {
	cache, err := lru.New[int, struct{}](2)
	require.NoError(t, err)

	cache.Add(1, struct{}{})
	require.True(t, cache.Contains(1))

	cache.Add(2, struct{}{})
	require.True(t, cache.Contains(1))
	require.True(t, cache.Contains(2))

	cache.Add(0, struct{}{})
	require.True(t, cache.Contains(0))
	require.True(t, cache.Contains(2))
	require.False(t, cache.Contains(1))

	// Check eviction works as expected. The least recently accessed item should be removed.
	cache.Contains(0)                                   // Access 0.
	cache.Add(3, struct{}{})                            // Access 3.
	require.ElementsMatch(t, cache.Keys(), []int{0, 3}) // Check 0 and 3.
}

func TestLruCache(t *testing.T) {
	N := 10
	cache := NewLruCache(N)

	// Add N ids.
	ids := random.RandomIDPtrsForTest(t, N)
	cache.AddIDs(ids...)
	for i, id := range ids {
		require.Truef(t, cache.Contains(id), "id at %d should be contained in cache", i)
	}

	// Add N more ids.
	newIds := random.RandomIDPtrsForTest(t, N)
	cache.AddIDs(newIds...)
	for i, id := range newIds {
		require.Truef(t, cache.Contains(id), "id at %d should be contained in cache", i)
	}
	for i, id := range ids {
		require.Falsef(t, cache.Contains(id), "id at %d should not be contained in cache", i)
	}
}
