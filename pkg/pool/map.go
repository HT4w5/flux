package pool

import "sync"

type MapPool[K comparable, V any] struct {
	pool sync.Pool
	size int
}

func NewMapPool[K comparable, V any](size int) *MapPool[K, V] {
	return &MapPool[K, V]{
		size: size,
		pool: sync.Pool{
			New: func() any {
				return make(map[K]V, size)
			},
		},
	}
}

func (p *MapPool[K, V]) Get() map[K]V {
	return p.pool.Get().(map[K]V)
}

func (p *MapPool[K, V]) Put(m map[K]V) {
	// Discard if grown
	if len(m) > p.size {
		return
	}
	clear(m)
	p.pool.Put(m)
}
