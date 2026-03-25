package index

import (
	"encoding/binary"
	"time"
)

type cachePayload struct {
	size      int64
	expiresAt time.Time
}

func (p *cachePayload) write(b []byte) {
	binary.BigEndian.PutUint64(b, uint64(p.size))
	binary.BigEndian.PutUint64(b[8:], uint64(p.expiresAt.Unix()))
}

func (p *cachePayload) read(b []byte) {
	p.size = int64(binary.BigEndian.Uint64(b))
	p.expiresAt = time.Unix(int64(binary.BigEndian.Uint64(b[8:])), 0)
}
