package db

import (
	"fmt"
	"sync"
)

type SharedMap struct {
	domainsBeingProcessed map[[32]byte]byte
	domainMutex           sync.Mutex
}

func NewSharedMap() *SharedMap {
	return &SharedMap{domainsBeingProcessed: make(map[[32]byte]byte)}
}

func (sharedMap *SharedMap) TryLock(keys [][32]byte) error {
	sharedMap.domainMutex.Lock()
	defer sharedMap.domainMutex.Unlock()
	for _, key := range keys {
		_, ok := sharedMap.domainsBeingProcessed[key]
		if ok {
			return ErrorResourceLocked
		}
	}

	for _, key := range keys {
		sharedMap.domainsBeingProcessed[key] = 1
	}
	return nil
}

func (sharedMap *SharedMap) Unlock(keys [][32]byte) error {
	sharedMap.domainMutex.Lock()
	defer sharedMap.domainMutex.Unlock()
	for _, key := range keys {
		_, ok := sharedMap.domainsBeingProcessed[key]
		if !ok {
			return fmt.Errorf("Unlock | try to unlock not locked resources")
		}
		delete(sharedMap.domainsBeingProcessed, key)
	}
	return nil
}
