package engine

import (
	"encoding/binary"
)

// --- Common header ---

type payloadHeader struct {
	lastUpdate int64
}

func (h *payloadHeader) encode(b []byte) {
	binary.BigEndian.PutUint64(b, uint64(h.lastUpdate))
}

func (h *payloadHeader) decode(b []byte) {
	h.lastUpdate = int64(binary.BigEndian.Uint64(b))
}

// --- Byte payload ---

type bytePayloadBuf [16]byte
type bytePayload struct {
	payloadHeader
	value int64
}

func (p *bytePayload) encode(b []byte) {
	p.payloadHeader.encode(b)
	binary.BigEndian.PutUint64(b[8:], uint64(p.value))
}

func (p *bytePayload) decode(b []byte) {
	p.payloadHeader.decode(b)
	p.value = int64(binary.BigEndian.Uint64(b[8:]))
}

// --- Count payload ---

type countPayloadBuf [12]byte
type countPayload struct {
	payloadHeader
	count uint32
}

func (p *countPayload) encode(b []byte) {
	p.payloadHeader.encode(b)
	binary.BigEndian.PutUint32(b[8:], p.count)
}

func (p *countPayload) decode(b []byte) {
	p.payloadHeader.decode(b)
	p.count = binary.BigEndian.Uint32(b[8:])
}
