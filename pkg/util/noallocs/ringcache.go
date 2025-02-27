package noallocs

type RingCache[T any] struct {
	currentIndex int
	size         int
	elements     []T
}

func NewRingCache[T any](size int, options ...ringCacheOpts[T]) *RingCache[T] {
	rc := &RingCache[T]{
		currentIndex: 0,
		size:         size,
		elements:     make([]T, size),
	}
	for _, o := range options {
		o(rc)
	}
	return rc
}

func (rc RingCache[T]) Current() T {
	return rc.elements[rc.currentIndex]
}

func (rc *RingCache[T]) Next() {
	rc.currentIndex = (rc.currentIndex + 1) % rc.size
}

func (rc *RingCache[T]) Rotate() T {
	curr := rc.Current()
	rc.Next()
	return curr
}

type ringCacheOpts[T any] func(*RingCache[T])

func WithPerNewElement[T any](perElement func(*T)) func(*RingCache[T]) {
	return func(rc *RingCache[T]) {
		for i := range rc.elements {
			perElement(&rc.elements[i])
		}
	}
}
