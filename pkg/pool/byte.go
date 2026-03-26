package pool

import "sync"

type BytePool struct {
	size int
	pool sync.Pool
}

func NewBytePool(size int) *BytePool {
	return &BytePool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				return make([]byte, size)
			},
		},
	}
}

func (p *BytePool) Get() []byte {
	return p.pool.Get().([]byte)[:p.size]
}

func (p *BytePool) Put(b []byte) {
	// Discard if grown
	if cap(b) != p.size {
		return
	}
	p.pool.Put(b)
}
