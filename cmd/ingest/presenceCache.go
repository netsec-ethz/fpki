package main

import (
	"sync"

	"github.com/netsec-ethz/fpki/pkg/common"
)

const initialNumberOfElements = 1000000 // 1 million

// PresenceCache is, for now, just a set. It will consume memory unstoppably.
type PresenceCache struct {
	set      set
	addingMu sync.RWMutex
}

type set map[common.SHA256Output]struct{}

func NewPresenceCache() *PresenceCache {
	return &PresenceCache{
		set: make(set, initialNumberOfElements),
	}
}

func (c *PresenceCache) Contains(id *common.SHA256Output) bool {
	c.addingMu.RLock()
	defer c.addingMu.RUnlock()

	_, ok := c.set[*id]
	return ok
}

// AddIDs is thread safe.
func (c *PresenceCache) AddIDs(ids []*common.SHA256Output) {
	c.addingMu.Lock()
	defer c.addingMu.Unlock()

	for _, id := range ids {
		c.set[*id] = struct{}{}
	}
}
