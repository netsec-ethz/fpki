package cache

import "github.com/netsec-ethz/fpki/pkg/common"

type NoCache struct{}

var _ Cache = (*NoCache)(nil)

func NewNoCache() NoCache {
	return NoCache{}
}

// Contains always returns false (the item is never in cache).
func (NoCache) Contains(*common.SHA256Output) bool {
	return false
}

// AddIDs doesn't do anything.
func (NoCache) AddIDs(...*common.SHA256Output) {}
