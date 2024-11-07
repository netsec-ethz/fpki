package cache

import "github.com/netsec-ethz/fpki/pkg/common"

type LruCache struct{}

func NewLruCache() LruCache {
	return LruCache{}
}

var _ Cache = (*LruCache)(nil)

// Contains always returns false (the item is never in cache).
func (LruCache) Contains(*common.SHA256Output) bool {
	return false
}

// AddIDs doesn't do anything.
func (LruCache) AddIDs(...*common.SHA256Output) {}
