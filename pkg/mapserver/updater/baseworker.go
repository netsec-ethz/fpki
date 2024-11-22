package updater

const ringCacheN = 2

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
	// Reuse storage.
	rc.elements[rc.currentIndex] = rc.elements[rc.currentIndex][:0]
	// Point to next cache.
	rc.currentIndex = (rc.currentIndex + 1) % ringCacheN
}
