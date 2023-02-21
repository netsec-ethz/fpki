package main

import (
	"sync"
	"unsafe"

	"github.com/netsec-ethz/fpki/pkg/common"
	"go.uber.org/atomic"
)

const initialNumberOfElements = 1000000 // 1 million

// PresenceCache is, for now, just a set. It will consume memory unstoppably.
type PresenceCache struct {
	ptr      atomic.UnsafePointer // Pointer to the data.
	addingMu sync.Mutex
}

type set map[common.SHA256Output]struct{}

func NewPresenceCache() *PresenceCache {
	set := make(set, initialNumberOfElements)
	return &PresenceCache{
		ptr: *atomic.NewUnsafePointer(unsafe.Pointer(&set)),
	}
}

func (c *PresenceCache) Contains(id *common.SHA256Output) bool {
	s := *c.getSet()
	_, ok := s[*id]
	return ok
}

// AddIDs is thread safe. This function does the following:
// 1. Copy the set to a local variable.
// 2. Modify the local copy.
// 3. Thread-safely modify the pointer to the set.
func (c *PresenceCache) AddIDs(ids []*common.SHA256Output) {
	c.addingMu.Lock()
	defer c.addingMu.Unlock()

	// Copy the local contents.
	newSet := *c.cloneSet()
	// Add the batch.
	for _, id := range ids {
		newSet[*id] = struct{}{}
	}
	// Modify the pointer to the set.
	ptr := unsafe.Pointer(&newSet)
	c.ptr.Swap(ptr)
}

func (c *PresenceCache) getSet() *set {
	ptr := c.ptr.Load()
	return (*set)(ptr)
}

func (c *PresenceCache) cloneSet() *set {
	s := *c.getSet()
	clone := make(set, len(s))
	for k, v := range s {
		clone[k] = v
	}
	return &clone
}
