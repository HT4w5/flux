package engine

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/docker/go-units"
)

type CacheDump map[string]any

type ByteBucketDump struct {
	Entries    map[string]ByteBucketEntryDump `json:"entries"`
	Name       string                         `json:"name"`
	EntryCount int                            `json:"entry_count"`
}

type ByteBucketEntryDump struct {
	ByteCount  string `json:"byte_count"`
	LastUpdate string `json:"last_update"`
}

type FreqBucketDump struct {
	Entries    map[string]FreqBucketEntryDump `json:"entries"`
	Name       string                         `json:"name"`
	EntryCount int                            `json:"entry_count"`
}

type FreqBucketEntryDump struct {
	LastUpdate   string `json:"last_update"`
	RequestCount uint32 `json:"request_count"`
}

type FileRatioBucketDump struct {
	Entries      map[string]map[string]FileRatioBucketEntryDump `json:"entries"`
	Name         string                                         `json:"name"`
	VolumeMethod string                                         `json:"volume_method"`
	EntryCount   int                                            `json:"entry_count"`
}

type FileRatioBucketEntryDump struct {
	ByteCount  string `json:"byte_count"`
	LastUpdate string `json:"last_update"`
}

func (re *RuleEngine) DumpCache() CacheDump {
	if re.state.Load() != engineRunning {
		re.logger.Warn("DumpCache: engine not running")
		return CacheDump{}
	}

	byteBuckets := make(map[bucketID]ByteBucketDump)
	freqBuckets := make(map[bucketID]FreqBucketDump)
	fileRatioBuckets := make(map[bucketID]FileRatioBucketDump)

	for _, b := range re.bucketMap {
		switch v := b.(type) {
		case *exprByteBucket:
			byteBuckets[b.id()] = ByteBucketDump{
				Name:    b.name(),
				Entries: make(map[string]ByteBucketEntryDump),
			}
		case *exprFreqBucket:
			freqBuckets[b.id()] = FreqBucketDump{
				Name:    b.name(),
				Entries: make(map[string]FreqBucketEntryDump),
			}
		case *exprFileRatioBucket:
			fileRatioBuckets[b.id()] = FileRatioBucketDump{
				Name:         b.name(),
				VolumeMethod: v.volume.name(),
				Entries:      make(map[string]map[string]FileRatioBucketEntryDump),
			}
		}
	}

	it := re.cache.Iterator()
	kBuf := re.keyBufferPool.Get()
	vBuf := re.keyBufferPool.Get()
	defer re.keyBufferPool.Put(kBuf)
	defer re.keyBufferPool.Put(vBuf)

	for {
		k, v, ok := it.GetNext(kBuf, vBuf)
		if !ok {
			break
		}

		if len(k) < 2 {
			re.logger.Warn("DumpCache: corrupt key encountered", "key", k)
			continue
		}

		id := bucketID(binary.BigEndian.Uint16(k[:2]))

		b, ok := re.bucketMap[id]
		if !ok {
			re.logger.Warn("DumpCache: unknown bucket id in cache", "id", id)
			continue
		}

		switch b.(type) {
		case *exprByteBucket:
			if len(k) < 18 || len(v) < 16 {
				re.logger.Warn("DumpCache: corrupt entry encountered", "key", k, "value", v)
				continue
			}
			addr := netip.AddrFrom16([16]byte(k[2:18])).Unmap()
			var payload bytePayload
			payload.decode(v)

			bkt := byteBuckets[id]

			bkt.Entries[addr.String()] = ByteBucketEntryDump{
				ByteCount:  units.HumanSize(float64(payload.value)),
				LastUpdate: time.Unix(payload.lastUpdate, 0).Format(time.RFC3339),
			}
			bkt.EntryCount++

			byteBuckets[id] = bkt
		case *exprFreqBucket:
			if len(k) < 18 || len(v) < 12 {
				re.logger.Warn("DumpCache: corrupt entry encountered", "key", k, "value", v)
				continue
			}
			addr := netip.AddrFrom16([16]byte(k[2:18])).Unmap()
			var payload countPayload
			payload.decode(v)

			bkt := freqBuckets[id]

			bkt.Entries[addr.String()] = FreqBucketEntryDump{
				RequestCount: payload.count,
				LastUpdate:   time.Unix(payload.lastUpdate, 0).Format(time.RFC3339),
			}
			bkt.EntryCount++

			freqBuckets[id] = bkt
		case *exprFileRatioBucket:
			if len(k) < 18 || len(v) < 16 {
				re.logger.Warn("DumpCache: corrupt entry encountered", "key", k, "value", v)
				continue
			}
			addr := netip.AddrFrom16([16]byte(k[2:18])).Unmap()
			path := string(k[18:])
			var payload bytePayload
			payload.decode(v)

			bkt := fileRatioBuckets[id]

			client := bkt.Entries[addr.String()]

			if client == nil {
				client = make(map[string]FileRatioBucketEntryDump)
				bkt.Entries[addr.String()] = client
			}

			client[path] = FileRatioBucketEntryDump{
				ByteCount:  units.HumanSize(float64(payload.value)),
				LastUpdate: time.Unix(payload.lastUpdate, 0).Format(time.RFC3339),
			}

			bkt.EntryCount++

			fileRatioBuckets[id] = bkt
		}
	}

	cd := make(CacheDump, len(re.bucketMap))

	for _, v := range byteBuckets {
		cd[v.Name] = v
	}

	for _, v := range freqBuckets {
		cd[v.Name] = v
	}

	for _, v := range fileRatioBuckets {
		cd[v.Name] = v
	}

	return cd
}
