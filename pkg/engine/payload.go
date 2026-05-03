package engine

import (
	"encoding/binary"
)

type byteBucketBuf [16]byte

type byteBucketPayload struct {
	byteCount  int64
	lastUpdate int64
}

func (p *byteBucketPayload) write(b []byte) {
	binary.NativeEndian.PutUint64(b, uint64(p.byteCount))
	binary.NativeEndian.PutUint64(b[8:], uint64(p.lastUpdate))
}

func (p *byteBucketPayload) read(b []byte) {
	p.byteCount = int64(binary.NativeEndian.Uint64(b))
	p.lastUpdate = int64(binary.NativeEndian.Uint64(b[8:]))
}

type freqBucketBuf [16]byte

type freqBucketPayload struct {
	requestCount int64
	lastUpdate   int64
}

func (p *freqBucketPayload) write(b []byte) {
	binary.NativeEndian.PutUint64(b, uint64(p.requestCount))
	binary.NativeEndian.PutUint64(b[8:], uint64(p.lastUpdate))
}

func (p *freqBucketPayload) read(b []byte) {
	p.requestCount = int64(binary.NativeEndian.Uint64(b))
	p.lastUpdate = int64(binary.NativeEndian.Uint64(b[8:]))
}

type fileRatioBucketBuf [16]byte

type fileRatioBucketPayload struct {
	byteCount  int64
	lastUpdate int64
}

func (p *fileRatioBucketPayload) write(b []byte) {
	binary.NativeEndian.PutUint64(b, uint64(p.byteCount))
	binary.NativeEndian.PutUint64(b[8:], uint64(p.lastUpdate))
}

func (p *fileRatioBucketPayload) read(b []byte) {
	p.byteCount = int64(binary.NativeEndian.Uint64(b))
	p.lastUpdate = int64(binary.NativeEndian.Uint64(b[8:]))
}
