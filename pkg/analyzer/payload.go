package analyzer

import (
	"encoding/binary"
	"time"
)

type clientPayloadBuf [20]byte

type clientPayload struct {
	requestCount int32
	byteCount    int64
	lastUpdate   time.Time
}

func (p *clientPayload) write(b []byte) {
	binary.BigEndian.PutUint32(b, uint32(p.requestCount))
	binary.BigEndian.PutUint64(b[4:], uint64(p.byteCount))
	binary.BigEndian.PutUint64(b[12:], uint64(p.lastUpdate.Unix()))
}

func (p *clientPayload) read(b []byte) {
	p.requestCount = int32(binary.BigEndian.Uint32(b))
	p.byteCount = int64(binary.BigEndian.Uint64(b[4:]))
	p.lastUpdate = time.Unix(int64(binary.BigEndian.Uint64(b[12:])), 0)
}

type clientPathPayloadBuf [16]byte

type clientPathPayload struct {
	fileRatio  int64 // unit: 1/1e5 files
	lastUpdate time.Time
}

func (p *clientPathPayload) write(b []byte) {
	binary.BigEndian.PutUint64(b, uint64(p.fileRatio))
	binary.BigEndian.PutUint64(b[8:], uint64(p.lastUpdate.Unix()))
}

func (p *clientPathPayload) read(b []byte) {
	p.fileRatio = int64(binary.BigEndian.Uint64(b))
	p.lastUpdate = time.Unix(int64(binary.BigEndian.Uint64(b[8:])), 0)
}
