package analyzer

import (
	"encoding/binary"
	"net/netip"
	"time"
)

type clientPayloadBuf [20]byte

type clientPayload struct {
	RequestCount int32     `json:"request_count"`
	ByteCount    int64     `json:"byte_count"`
	LastUpdate   time.Time `json:"last_update"`
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
	FileRatio  int64     `json:"file_ratio"` // unit: 1/1e5 files
	LastUpdate time.Time `json:"last_update"`
}

func (p *clientPathPayload) write(b []byte) {
	binary.BigEndian.PutUint64(b, uint64(p.FileRatio))
	binary.BigEndian.PutUint64(b[8:], uint64(p.LastUpdate.Unix()))
}

func (p *clientPathPayload) read(b []byte) {
	p.FileRatio = int64(binary.BigEndian.Uint64(b))
	p.LastUpdate = time.Unix(int64(binary.BigEndian.Uint64(b[8:])), 0)
}

type ClientBucket struct {
	Addr netip.Addr `json:"addr"`
	clientPayload
}

type ClientPathBucket struct {
	Addr netip.Addr `json:"addr"`
	Path string     `json:"path"`
	clientPathPayload
}

type CacheDump struct {
	ClientBuckets     []ClientBucket     `json:"client_buckets"`
	ClientPathBuckets []ClientPathBucket `json:"client_path_buckets"`
}
