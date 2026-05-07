package engine

import (
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
	RequestCount int64  `json:"request_count"`
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
	byteBuckets := make(map[byte]ByteBucketDump)
	freqBuckets := make(map[byte]FreqBucketDump)
	fileRatioBuckets := make(map[byte]FileRatioBucketDump)

	for _, b := range re.bucketMap {
		switch v := b.(type) {
		case *exprByteBucket:
			byteBuckets[b.prefix()] = ByteBucketDump{
				Name:    b.name(),
				Entries: make(map[string]ByteBucketEntryDump),
			}
		case *exprFreqBucket:
			freqBuckets[b.prefix()] = FreqBucketDump{
				Name:    b.name(),
				Entries: make(map[string]FreqBucketEntryDump),
			}
		case *exprFileRatioBucket:
			fileRatioBuckets[b.prefix()] = FileRatioBucketDump{
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

		if len(k) < 1 {
			re.logger.Warn("DumpCache: corrupt key encountered", "key", k)
			continue
		}

		switch re.bucketMap[k[0]].(type) {
		case *exprByteBucket:
			if len(k) < 17 || len(v) < 16 {
				re.logger.Warn("DumpCache: corrupt entry encountered", "key", k, "value", v)
				continue
			}
			addr := netip.AddrFrom16([16]byte(k[1:17])).Unmap()
			var payload byteBucketPayload
			payload.read(v)

			bkt := byteBuckets[k[0]]

			bkt.Entries[addr.String()] = ByteBucketEntryDump{
				ByteCount:  units.HumanSize(float64(payload.byteCount)),
				LastUpdate: time.Unix(payload.lastUpdate, 0).Format(time.RFC3339),
			}
			bkt.EntryCount++

			byteBuckets[k[0]] = bkt
		case *exprFreqBucket:
			if len(k) < 17 || len(v) < 16 {
				re.logger.Warn("DumpCache: corrupt entry encountered", "key", k, "value", v)
				continue
			}
			addr := netip.AddrFrom16([16]byte(k[1:17])).Unmap()
			var payload freqBucketPayload
			payload.read(v)

			bkt := freqBuckets[k[0]]

			bkt.Entries[addr.String()] = FreqBucketEntryDump{
				RequestCount: payload.requestCount,
				LastUpdate:   time.Unix(payload.lastUpdate, 0).Format(time.RFC3339),
			}
			bkt.EntryCount++

			freqBuckets[k[0]] = bkt
		case *exprFileRatioBucket:
			if len(k) < 17 || len(v) < 16 {
				re.logger.Warn("DumpCache: corrupt entry encountered", "key", k, "value", v)
				continue
			}
			addr := netip.AddrFrom16([16]byte(k[1:17])).Unmap()
			path := string(k[17:])
			var payload fileRatioBucketPayload
			payload.read(v)

			bkt := fileRatioBuckets[k[0]]

			client := bkt.Entries[addr.String()]

			if client == nil {
				client = make(map[string]FileRatioBucketEntryDump)
				bkt.Entries[addr.String()] = client
			}

			client[path] = FileRatioBucketEntryDump{
				ByteCount:  units.HumanSize(float64(payload.byteCount)),
				LastUpdate: time.Unix(payload.lastUpdate, 0).Format(time.RFC3339),
			}

			bkt.EntryCount++

			fileRatioBuckets[k[0]] = bkt
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
