package updater

import "github.com/netsec-ethz/fpki/pkg/util/noallocs"

func createFilepathRingCache() noallocs.RingCache[[]byte] {
	return *noallocs.NewRingCache[[]byte](FilepathCacheSize, noallocs.WithPerNewElement(
		func(t *[]byte) {
			*t = make([]byte, FilepathLen)
		}),
	)
}

// ringCacheN has size 3 to allow concurrent access to:
// 1. In-flight (downstream) to next stage.
// 2. Actively being zeroed.
// 3. Actively being filled from previous stage.
const ringCacheN = 3

type ringCache[T any] struct {
	currentIndex int
	elements     [ringCacheN][]T
}

func newRingCache[T any](preAllocatedSize int) ringCache[T] {
	rc := ringCache[T]{}
	for i := 0; i < ringCacheN; i++ {
		rc.elements[i] = make([]T, 0, preAllocatedSize)
	}
	return rc
}

func (rc ringCache[T]) current() []T {
	return rc.elements[rc.currentIndex]
}

func (rc ringCache[T]) currLength() int {
	return len(rc.current())
}

func (rc *ringCache[T]) addElem(elem T) {
	rc.elements[rc.currentIndex] = append(rc.elements[rc.currentIndex], elem)
}

func (rc *ringCache[T]) rotate() {
	// Switch to the alternate buffer first so the slice just handed downstream keeps its payload.
	rc.currentIndex = (rc.currentIndex + 1) % ringCacheN

	// Clear the buffer we are about to reuse so stale pointers from the previous cycle do not
	// keep payloads reachable until overwritten.
	clear(rc.elements[rc.currentIndex])
	rc.elements[rc.currentIndex] = rc.elements[rc.currentIndex][:0]
}
