package main

import (
	"sync"

	"github.com/netsec-ethz/fpki/pkg/common"
	"go.uber.org/atomic"
)

const initialNumberOfElements = 1000000 // 1 million

// PresenceCache is, for now, just a set. It will consume memory unstoppably.
type PresenceCache struct {
	sets        [2]set          // A regular set and its "shadow" (always a copy)
	currentIdx  atomic.Uint32   // The index of the current set.
	readerCount [2]atomic.Int32 // How many routines reading from sets[0]

	addingMu sync.Mutex
}

type set map[common.SHA256Output]struct{}

func NewPresenceCache() *PresenceCache {

	sets := [...]set{
		make(set, initialNumberOfElements),
		make(set, initialNumberOfElements),
	}
	return &PresenceCache{
		sets: sets,
		// currentIdx: *atomic.NewUint32(0),
	}
}

func (c *PresenceCache) Contains(id *common.SHA256Output) bool {
	// To avoid race conditions, we must double check that the index didn't change before we were
	// able to increment the reader counter. If it changed, repeat the operation.
	for {
		idx := c.currentIdx.Load()
		c.readerCount[idx].Inc()
		if c.currentIdx.Load() != idx {
			// The writting routine won the race: unroll increment and repeat operation.
			c.readerCount[idx].Dec()
			continue
		}
		defer c.readerCount[idx].Dec()
		s := c.sets[int(idx)]
		_, ok := s[*id]
		return ok
	}
}

// AddIDs is thread safe.
func (c *PresenceCache) AddIDs(ids []*common.SHA256Output) {
	c.addingMu.Lock()
	defer c.addingMu.Unlock()

	// Futex until all the readers have left the shadow (should almost always be noop).
	for {
		if c.readerCount[1].Load() == 0 {
			break
		}
		// fmt.Println("shadow busy")
	}
	// Copy the local contents to the shadow.
	for _, id := range ids {
		c.sets[1][*id] = struct{}{}
	}
	// Modify the pointer to the set.
	c.currentIdx.Store(1)
	// Futex until all the readers have left current.
	for {
		if c.readerCount[0].Load() == 0 {
			break
		}
		// fmt.Println("principal busy")
	}
	// Copy to current.
	for _, id := range ids {
		c.sets[0][*id] = struct{}{}
	}
	// Point back current.
	c.currentIdx.Store(0)
}

func (c *PresenceCache) Size() int {
	return len(c.sets[0])
}
