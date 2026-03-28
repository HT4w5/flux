package analyzer

import (
	"context"
	"net/netip"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/VictoriaMetrics/fastcache"
)

const (
	requestBucketOverflowBlame = "request count bucket overflow"
	byteBucketOverflowBlame    = "byte count bucket overflow"
	fileBucketOverflowBlame    = "file ratio bucket overflow"
)

/*
Cache key definitions:
- client bucket: <addr_bytes>
- client-path bucket: <addr_bytes>:<path_bytes>
*/

// For request and byte count bucket
func (a *Analyzer) updateClientBucket(ctx context.Context, request *dto.Request) {
	var buf clientPayloadBuf
	var bkt clientPayload
	key := request.Client.As16()
	_, ok := a.bucketCache.HasGet(buf[:], key[:])
	if ok {
		bkt.read(buf[:])
	}

	bkt.requestCount++
	bkt.byteCount += request.Sent
	timeDelta := request.Time.Unix() - bkt.lastUpdate.Unix()
	if timeDelta > 0 {
		bkt.requestCount -= int32(a.config.RequestLeak) * int32(timeDelta)
		bkt.byteCount -= a.config.ByteLeak * timeDelta
		bkt.lastUpdate = request.Time
	}

	// Check for overflow
	if int(bkt.requestCount) > a.config.RequestVolume {
		a.logger.Debug("request count bucket overflow", "client", request.Client.String(), "count", bkt.requestCount)
		var prefixLen int
		if request.Client.Is4() {
			prefixLen = a.config.IPv4BanPrefixLen
		} else {
			prefixLen = a.config.IPv6BanPrefixLen
		}
		a.jail.Add(ctx, &dto.BanRecord{
			Prefix:    netip.PrefixFrom(request.Client, prefixLen),
			Blame:     requestBucketOverflowBlame,
			ExpiresAt: bkt.lastUpdate.Add(a.config.RequestBanDuration),
		})
		// Stop tracking
		a.bucketCache.Del(key[:])
		return
	}

	if bkt.byteCount > a.config.ByteVolume {
		a.logger.Debug("byte count bucket overflow", "client", request.Client.String(), "count", bkt.byteCount)
		var prefixLen int
		if request.Client.Is4() {
			prefixLen = a.config.IPv4BanPrefixLen
		} else {
			prefixLen = a.config.IPv6BanPrefixLen
		}
		a.jail.Add(ctx, &dto.BanRecord{
			Prefix:    netip.PrefixFrom(request.Client, prefixLen),
			Blame:     byteBucketOverflowBlame,
			ExpiresAt: bkt.lastUpdate.Add(a.config.ByteBanDuration),
		})
		// Stop tracking
		a.bucketCache.Del(key[:])
		return
	}

	bkt.write(buf[:])

	a.bucketCache.Set(key[:], buf[:])
}

const (
	fileRatioPrecision = 1e5
)

// For file ratio bucket
func (a *Analyzer) updateClientPathBucket(ctx context.Context, request *dto.Request) {
	// Query file size index
	size, ok := a.index.GetSize([]byte(request.URL))
	if !ok {
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
	}

	// Calculate ratio increment
	// Scale up for 2 decimals of precision
	bkt.fileRatio += (request.Sent * fileRatioPrecision) / (size * fileRatioPrecision)

	timeDelta := request.Time.Unix() - bkt.lastUpdate.Unix()
	if timeDelta > 0 {
		bkt.fileRatio -= a.config.FileRatioLeak * timeDelta
		bkt.lastUpdate = request.Time
	}

	// Check for overflow
	if bkt.fileRatio > a.config.FileRatioVolume {
		a.logger.Debug("file ratio bucket overflow", "client", request.Client.String(), "path", request.URL, "ratio", bkt.fileRatio)
		var prefixLen int
		if request.Client.Is4() {
			prefixLen = a.config.IPv4BanPrefixLen
		} else {
			prefixLen = a.config.IPv6BanPrefixLen
		}
		a.jail.Add(ctx, &dto.BanRecord{
			Prefix:    netip.PrefixFrom(request.Client, prefixLen),
			Blame:     fileBucketOverflowBlame,
			ExpiresAt: bkt.lastUpdate.Add(a.config.FileRatioBanDuration),
		})
		// Stop tracking
		a.bucketCache.Del(key[:])
		return
	}

	bkt.write(buf[:])

	a.bucketCache.Set(key[:], buf[:])
}

func (a *Analyzer) GetStats() fastcache.Stats {
	var s fastcache.Stats
	a.bucketCache.UpdateStats(&s)
	return s
}
