package analyzer

import (
	"encoding/binary"
	"net/netip"
	"time"
)

type clientPayloadBuf [20]byte

type clientPayload struct {
	LastUpdate   time.Time `json:"last_update"`
	ByteCount    int64     `json:"byte_count"`
	RequestCount int32     `json:"request_count"`
}

func (p *clientPayload) write(b []byte) {
	binary.BigEndian.PutUint32(b, uint32(p.RequestCount))
	binary.BigEndian.PutUint64(b[4:], uint64(p.ByteCount))
	binary.BigEndian.PutUint64(b[12:], uint64(p.LastUpdate.Unix()))
}

func (p *clientPayload) read(b []byte) {
	p.RequestCount = int32(binary.BigEndian.Uint32(b))
	p.ByteCount = int64(binary.BigEndian.Uint64(b[4:]))
	p.LastUpdate = time.Unix(int64(binary.BigEndian.Uint64(b[12:])), 0)
}

type clientPathPayloadBuf [16]byte

type clientPathPayload struct {
	LastUpdate time.Time `json:"last_update"`
	Sent       int64     `json:"sent"`
}

func (p *clientPathPayload) write(b []byte) {
	binary.BigEndian.PutUint64(b, uint64(p.Sent))
	binary.BigEndian.PutUint64(b[8:], uint64(p.LastUpdate.Unix()))
}

func (p *clientPathPayload) read(b []byte) {
	p.Sent = int64(binary.BigEndian.Uint64(b))
	p.LastUpdate = time.Unix(int64(binary.BigEndian.Uint64(b[8:])), 0)
}

type ClientBucket struct {
	Addr netip.Addr `json:"addr"`
	clientPayload
}

type ClientPathBucket struct {
	clientPathPayload
	Addr netip.Addr `json:"addr"`
	Path string     `json:"path"`
}

type CacheDump struct {
	ClientBuckets     []ClientBucket     `json:"client_buckets"`
	ClientPathBuckets []ClientPathBucket `json:"client_path_buckets"`
}
