package analyzer

import (
	"context"
	"net/netip"

	"github.com/HT4w5/cache"
	"github.com/HT4w5/flux/pkg/dto"
)

const (
	requestBucketOverflowBlame = "request count bucket overflow"
	byteBucketOverflowBlame    = "byte count bucket overflow"
	fileBucketOverflowBlame    = "file ratio bucket overflow"
)

/*
Cache key definitions:
- client bucket: <addr_bytes> (IPv4 as IPv4-in-IPv6)
- client-path bucket: <addr_bytes><path_bytes> (IPv4 as IPv4-in-IPv6)
*/

// For request and byte count bucket
func (a *Analyzer) updateClientBucket(ctx context.Context, request *dto.Request) {
	var buf clientPayloadBuf
	var bkt clientPayload
	key := request.Client.As16()
	_, ok := a.bucketCache.HasGet(buf[:], key[:])
	if ok {
		bkt.read(buf[:])
		a.logger.Debug("got client cache object", "key", key, "object", bkt)
	} else {
		a.logger.Debug("client cache miss; creating new")
	}

	bkt.RequestCount++
	bkt.ByteCount += request.Sent
	timeDelta := request.Time.Unix() - bkt.LastUpdate.Unix()
	if timeDelta > 0 {
		requestLeaked := a.config.RequestLeak * int(timeDelta)
		if requestLeaked >= int(bkt.RequestCount) {
			bkt.RequestCount = 0
		} else {
			bkt.RequestCount -= int32(requestLeaked)
		}

		bkt.ByteCount = max(0, bkt.ByteCount-a.config.ByteLeak*timeDelta)
		byteLeaked := a.config.ByteLeak * timeDelta
		if byteLeaked >= bkt.ByteCount {
			bkt.ByteCount = 0
		} else {
			bkt.ByteCount -= byteLeaked
		}

		bkt.LastUpdate = request.Time
	}

	// Check for overflow
	if int(bkt.RequestCount) > a.config.RequestVolume {
		a.logger.Debug("request count bucket overflow", "client", request.Client.String(), "count", bkt.RequestCount)
		var prefixLen int
		if request.Client.Is4() {
			prefixLen = a.config.IPv4BanPrefixLen
		} else {
			prefixLen = a.config.IPv6BanPrefixLen
		}
		a.jail.Add(ctx, &dto.BanRecord{
			Prefix:    netip.PrefixFrom(request.Client, prefixLen),
			Blame:     requestBucketOverflowBlame,
			ExpiresAt: bkt.LastUpdate.Add(a.config.RequestBanDuration),
		})
		// Stop tracking
		a.bucketCache.Del(key[:])
		return
	}

	if bkt.ByteCount > a.config.ByteVolume {
		a.logger.Debug("byte count bucket overflow", "client", request.Client.String(), "count", bkt.ByteCount)
		var prefixLen int
		if request.Client.Is4() {
			prefixLen = a.config.IPv4BanPrefixLen
		} else {
			prefixLen = a.config.IPv6BanPrefixLen
		}
		a.jail.Add(ctx, &dto.BanRecord{
			Prefix:    netip.PrefixFrom(request.Client, prefixLen),
			Blame:     byteBucketOverflowBlame,
			ExpiresAt: bkt.LastUpdate.Add(a.config.ByteBanDuration),
		})
		// Stop tracking
		a.bucketCache.Del(key[:])
		return
	}

	a.logger.Debug("setting client cache object", "key", key, "object", bkt)
	bkt.write(buf[:])
	a.bucketCache.Set(key[:], buf[:])
}

// For file ratio bucket
func (a *Analyzer) updateClientPathBucket(ctx context.Context, request *dto.Request) {
	// Query file size index
	size, ok := a.index.GetSize([]byte(request.URL))
	if !ok || size == 0 {
		return // No size info, impossible to track
	}

	var buf clientPathPayloadBuf
	var bkt clientPathPayload
	keyBuffer := a.keyBufferPool.Get()
	defer a.keyBufferPool.Put(keyBuffer)
	keyBuffer = keyBuffer[:0]
	key := request.Client.As16()
	keyBuffer = append(keyBuffer, key[:]...)
	keyBuffer = append(keyBuffer, request.URL...)
	_, ok = a.bucketCache.HasGet(buf[:], keyBuffer)
	if ok {
		bkt.read(buf[:])
		a.logger.Debug("got client-path cache object", "key", keyBuffer, "object", bkt)
	} else {
		a.logger.Debug("client-path cache miss; creating new")
	}

	bkt.Sent += request.Sent

	timeDelta := request.Time.Unix() - bkt.LastUpdate.Unix()
	if timeDelta > 0 {
		leaked := int64(a.config.FileRatioLeak * float64(size*timeDelta))
		if leaked >= bkt.Sent {
			bkt.Sent = 0
		} else {
			bkt.Sent -= leaked
		}
		bkt.LastUpdate = request.Time
	}

	// Check for overflow
	if bkt.Sent > int64(a.config.FileRatioVolume*float64(size)) {
		a.logger.Debug("file ratio bucket overflow", "client", request.Client.String(), "path", request.URL, "sent", bkt.Sent)
		var prefixLen int
		if request.Client.Is4() {
			prefixLen = a.config.IPv4BanPrefixLen
		} else {
			prefixLen = a.config.IPv6BanPrefixLen
		}
		a.jail.Add(ctx, &dto.BanRecord{
			Prefix:    netip.PrefixFrom(request.Client, prefixLen),
			Blame:     fileBucketOverflowBlame,
			ExpiresAt: bkt.LastUpdate.Add(a.config.FileRatioBanDuration),
		})
		// Stop tracking
		a.bucketCache.Del(keyBuffer[:])
		return
	}

	a.logger.Debug("setting client-path cache object", "key", keyBuffer, "object", bkt)
	bkt.write(buf[:])
	a.bucketCache.Set(keyBuffer[:], buf[:])
}

func (a *Analyzer) GetStats() cache.Statistics {
	return a.bucketCache.Statistics()
}

func (a *Analyzer) DumpCache() CacheDump {
	d := CacheDump{
		ClientBuckets:     make([]ClientBucket, 0),
		ClientPathBuckets: make([]ClientPathBucket, 0),
	}

	it := a.bucketCache.Iterator()
	kBuf := a.keyBufferPool.Get()
	defer a.keyBufferPool.Put(kBuf)

	for {
		var vBuf [20]byte
		k, v, ok := it.GetNext(kBuf, vBuf[:])
		if !ok {
			break
		}

		var addr netip.Addr
		var path string
		if len(k) < 16 {
			a.logger.Warn("corrupt key encountered when dumping", "key", k)
			continue
		}
		addr = netip.AddrFrom16([16]byte(k[:16])).Unmap()
		if len(k) > 16 {
			path = string(k[16:])
		}

		switch len(v) {
		case 20:
			var p clientPayload
			p.read(v)
			d.ClientBuckets = append(d.ClientBuckets, ClientBucket{
				Addr:          addr,
				clientPayload: p,
			})
		case 16:
			var p clientPathPayload
			p.read(v)
			d.ClientPathBuckets = append(d.ClientPathBuckets, ClientPathBucket{
				Addr:              addr,
				Path:              path,
				clientPathPayload: p,
			})
		default:
			a.logger.Warn("invalid payload length", "length", len(v))
		}
	}

	return d
}
