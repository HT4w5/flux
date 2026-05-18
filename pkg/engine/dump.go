package engine

import (
	"errors"
	"iter"
	"net/netip"
	"time"
	"unsafe"

	"github.com/HT4w5/flux/pkg/cache"
	"github.com/docker/go-units"
)

type BucketInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Config any    `json:"config"`
}

var errEngineNotRunning = errors.New("engine not running")

func (re *RuleEngine) GetBuckets() ([]BucketInfo, error) {
	if re.state.Load() != engineRunning {
		return nil, errEngineNotRunning
	}

	var bktInfos []BucketInfo
	for name, bkt := range re.bucketMap {
		bktInfos = append(bktInfos, BucketInfo{
			Name:   name,
			Type:   bkt.typeName(),
			Config: bkt.config(),
		})
	}

	return bktInfos, nil
}

func (re *RuleEngine) GetBucketStatistics() (cache.Statistics, error) {
	if re.state.Load() != engineRunning {
		return cache.Statistics{}, errEngineNotRunning
	}

	return re.cache.Statistics(), nil
}

var errNoSuchBucket = errors.New("no such bucket")
var errBadBucketType = errors.New("bad bucket type")

func (re *RuleEngine) GetBucketEntries(bucket string) (iter.Seq[any], error) {
	if re.state.Load() != engineRunning {
		return nil, errEngineNotRunning
	}

	bkt, ok := re.bucketMap[bucket]
	if !ok {
		return nil, errNoSuchBucket
	}

	var buildEntry func(k string, v cache.CacheEntry) any

	switch bkt.typeName() {
	case "byte":
		buildEntry = buildByteBucketEntry
	case "freq":
		buildEntry = buildFreqBucketEntry
	case "file-ratio":
		buildEntry = buildFileRatioBucketEntry
	default:
		return nil, errBadBucketType
	}

	it := re.cache.Iterator(bucket)

	return func(yield func(any) bool) {
		it(func(k string, v cache.CacheEntry) bool {
			return yield(buildEntry(k, v))
		})
	}, nil
}

type errorEntry struct {
	Reason string `json:"reason"`
}

type byteBucketEntry struct {
	Addr        string `json:"addr"`
	Bytes       string `json:"bytes"`
	LastUpdated string `json:"last_updated"`
}

type freqBucketEntry struct {
	Addr        string `json:"addr"`
	Requests    int64  `json:"requests"`
	LastUpdated string `json:"last_updated"`
}

type fileRatioBucketEntry struct {
	Addr        string `json:"addr"`
	URL         string `json:"url"`
	Bytes       string `json:"bytes"`
	LastUpdated string `json:"last_updated"`
}

func buildByteBucketEntry(k string, v cache.CacheEntry) any {
	if len(k) < 16 {
		return errorEntry{
			Reason: "entry key too short",
		}
	}

	ptr := unsafe.StringData(k)
	bytes := *(*[16]byte)(unsafe.Pointer(ptr))
	addr := netip.AddrFrom16(bytes)

	return byteBucketEntry{
		Addr:        addr.Unmap().String(),
		Bytes:       units.HumanSize(float64(v.Value)),
		LastUpdated: time.Unix(v.LastUpdate, 0).Format(time.RFC3339),
	}
}

func buildFreqBucketEntry(k string, v cache.CacheEntry) any {
	if len(k) < 16 {
		return errorEntry{
			Reason: "entry key too short",
		}
	}

	ptr := unsafe.StringData(k)
	bytes := *(*[16]byte)(unsafe.Pointer(ptr))
	addr := netip.AddrFrom16(bytes)

	return freqBucketEntry{
		Addr:        addr.Unmap().String(),
		Requests:    v.Value,
		LastUpdated: time.Unix(v.LastUpdate, 0).Format(time.RFC3339),
	}
}

func buildFileRatioBucketEntry(k string, v cache.CacheEntry) any {
	if len(k) < 16 {
		return errorEntry{
			Reason: "entry key too short",
		}
	}

	ptr := unsafe.StringData(k)
	bytes := *(*[16]byte)(unsafe.Pointer(ptr))
	addr := netip.AddrFrom16(bytes)

	return fileRatioBucketEntry{
		Addr:        addr.Unmap().String(),
		URL:         k[16:],
		Bytes:       units.HumanSize(float64(v.Value)),
		LastUpdated: time.Unix(v.LastUpdate, 0).Format(time.RFC3339),
	}
}
