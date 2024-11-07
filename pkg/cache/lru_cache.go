package cache

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/netsec-ethz/fpki/pkg/common"
)

type LruCache struct {
	*lru.Cache[common.SHA256Output, struct{}]
}

var _ Cache = (*LruCache)(nil)

func NewLruCache(size int) *LruCache {
	cache, err := lru.New[common.SHA256Output, struct{}](size)
	if err != nil {
		panic(fmt.Errorf("cannot create cache: %s", err))
	}
	return &LruCache{
		Cache: cache,
	}
}

// Contains always returns false (the item is never in cache).
func (c *LruCache) Contains(id *common.SHA256Output) bool {
	return c.Cache.Contains(*id)
}

// AddIDs doesn't do anything.
func (c *LruCache) AddIDs(ids ...*common.SHA256Output) {
	for _, id := range ids {
		c.Cache.Add(*id, struct{}{})
	}
}
