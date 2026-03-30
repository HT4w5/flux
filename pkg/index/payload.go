package index

import (
	"encoding/binary"
	"time"
)

type payloadBuf [16]byte

type cachePayload struct {
	Size      int64     `json:"size"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (p *cachePayload) write(b []byte) {
	binary.BigEndian.PutUint64(b, uint64(p.Size))
	binary.BigEndian.PutUint64(b[8:], uint64(p.ExpiresAt.Unix()))
}

func (p *cachePayload) read(b []byte) {
	p.Size = int64(binary.BigEndian.Uint64(b))
	p.ExpiresAt = time.Unix(int64(binary.BigEndian.Uint64(b[8:])), 0)
}

type CacheDump struct {
	Path string `json:"path"`
	cachePayload
}
