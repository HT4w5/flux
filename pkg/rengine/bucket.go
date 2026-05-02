package rengine

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unsafe"

	"github.com/HT4w5/cache"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/pool"
	"github.com/docker/go-units"
)

const (
	maxBuckets = 256
)

var errTooManyBuckets = errors.New("max amount of buckets reached: " + strconv.Itoa(maxBuckets))

type bucketCommon struct {
	cache          *cache.Cache
	keyBufferPool  *pool.BytePool
	cacheKeyPrefix byte
}

func (bc *bucketCommon) prefix() byte {
	return bc.cacheKeyPrefix
}

type bucketType int

const (
	byteBucket bucketType = iota
	freqBucket
	fileRatioBucket
)

func (cb *chainBuilder) newBucketCommon() (bucketCommon, error) {
	if cb.bucketCounter >= maxBuckets {
		return bucketCommon{}, errTooManyBuckets
	}

	prefix := byte(cb.bucketCounter)
	cb.bucketCounter++

	return bucketCommon{
		cacheKeyPrefix: prefix,
		cache:          cb.re.cache,
		keyBufferPool:  cb.re.keyBufferPool,
	}, nil
}

// Bucket expressions

type exprBucket interface {
	match(ctx requestCtx, request *dto.Request) bool
	prefix() byte
	bucketType() bucketType
	name() string
}

type exprByteBucket struct {
	bucketCommon
	leak   int64
	volume int64
}

func (expr *exprByteBucket) bucketType() bucketType { return byteBucket }

func (expr *exprByteBucket) name() string {
	return "byte-bucket-" + strconv.FormatUint(uint64(expr.prefix()), 10)
}

func (expr *exprByteBucket) match(ctx requestCtx, request *dto.Request) bool {
	var buf byteBucketBuf
	var bkt byteBucketPayload

	keyBuffer := expr.keyBufferPool.Get()
	defer expr.keyBufferPool.Put(keyBuffer)
	keyBuffer = keyBuffer[:0]

	keyClientAddr := request.Client.As16()
	keyBuffer = append(keyBuffer, expr.cacheKeyPrefix)
	keyBuffer = append(keyBuffer, keyClientAddr[:]...)

	var timeDelta int64
	newBuf, ok := expr.cache.HasGet(buf[:], keyBuffer)
	if ok {
		bkt.read(newBuf)
		timeDelta = request.Time.Unix() - bkt.lastUpdate
	} else {
		bkt.lastUpdate = request.Time.Unix()
		timeDelta = 0
	}
	bkt.byteCount += request.Sent

	if timeDelta > 0 {
		bkt.byteCount = max(0, bkt.byteCount-expr.leak*timeDelta)
		bkt.lastUpdate = request.Time.Unix()
	}

	bkt.write(newBuf)
	expr.cache.Set(keyBuffer[:], newBuf)

	if bkt.byteCount > expr.volume {
		ctx.kv[ctxKeyBanReason] = banReasonByteOverflow
		ctx.kv[ctxKeyBanThreshold] = uint64(expr.volume)
		ctx.kv[ctxKeyBanValue] = uint64(bkt.byteCount)
		return true
	}
	return false
}

func (cb *chainBuilder) buildExprByteBucket(value any) (exprBucket, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("BYTE-BUCKET expression expects a string, got %T", value)
	}

	args := strings.Split(str, ",")
	if len(args) != 2 {
		return nil, fmt.Errorf("BYTE-BUCKET expression expects 2 arguments, got %d", len(args))
	}

	leak, err := units.FromHumanSize(args[0])
	if err != nil {
		leak, err = strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("BYTE-BUCKET expects integer/bytesize leak, got %s", args[0])
		}
	}

	if leak < 0 {
		return nil, fmt.Errorf("BYTE-BUCKET expects non-negative leak, got %d", leak)
	}

	volume, err := units.FromHumanSize(args[1])
	if err != nil {
		volume, err = strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("BYTE-BUCKET expects integer/bytesize volume, got %s", args[1])
		}
	}

	if volume < 0 {
		return nil, fmt.Errorf("BYTE-BUCKET expects non-negative volume, got %d", volume)
	}

	bc, err := cb.newBucketCommon()
	if err != nil {
		return nil, err
	}

	return &exprByteBucket{
		bucketCommon: bc,
		leak:         leak,
		volume:       volume,
	}, nil
}

type exprFreqBucket struct {
	bucketCommon
	leak   int64
	volume int64
}

func (expr *exprFreqBucket) bucketType() bucketType { return freqBucket }

func (expr *exprFreqBucket) name() string {
	return "freq-bucket-" + strconv.FormatUint(uint64(expr.prefix()), 10)
}

func (expr *exprFreqBucket) match(ctx requestCtx, request *dto.Request) bool {
	var buf freqBucketBuf
	var bkt freqBucketPayload

	keyBuffer := expr.keyBufferPool.Get()
	defer expr.keyBufferPool.Put(keyBuffer)
	keyBuffer = keyBuffer[:0]

	keyClientAddr := request.Client.As16()
	keyBuffer = append(keyBuffer, expr.cacheKeyPrefix)
	keyBuffer = append(keyBuffer, keyClientAddr[:]...)

	var timeDelta int64
	newBuf, ok := expr.cache.HasGet(buf[:], keyBuffer)
	if ok {
		bkt.read(newBuf)
		timeDelta = request.Time.Unix() - bkt.lastUpdate
	} else {
		bkt.lastUpdate = request.Time.Unix()
		timeDelta = 0
	}
	bkt.requestCount++

	if timeDelta > 0 {
		bkt.requestCount = max(0, bkt.requestCount-expr.leak*timeDelta)
		bkt.lastUpdate = request.Time.Unix()
	}

	bkt.write(newBuf)
	expr.cache.Set(keyBuffer[:], newBuf)

	if bkt.requestCount > expr.volume {
		ctx.kv[ctxKeyBanReason] = banReasonFreqOverflow
		ctx.kv[ctxKeyBanThreshold] = uint64(expr.volume)
		ctx.kv[ctxKeyBanValue] = uint64(bkt.requestCount)
		return true
	}
	return false
}

func (cb *chainBuilder) buildExprFreqBucket(value any) (exprBucket, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("FREQ-BUCKET expression expects a string, got %T", value)
	}

	args := strings.Split(str, ",")
	if len(args) != 2 {
		return nil, fmt.Errorf("FREQ-BUCKET expression expects 2 arguments, got %d", len(args))
	}

	leak, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("FREQ-BUCKET expects integer leak, got %s", args[0])
	}

	if leak < 0 {
		return nil, fmt.Errorf("FREQ-BUCKET expects non-negative leak, got %d", leak)
	}

	volume, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("FREQ-BUCKET expects integer volume, got %s", args[1])
	}

	if volume < 0 {
		return nil, fmt.Errorf("FREQ-BUCKET expects non-negative volume, got %d", volume)
	}

	bc, err := cb.newBucketCommon()
	if err != nil {
		return nil, err
	}

	return &exprFreqBucket{
		bucketCommon: bc,
		leak:         leak,
		volume:       volume,
	}, nil
}

type exprFileRatioBucket struct {
	index *index.FileSizeIndex
	bucketCommon
	leak   float64
	volume float64
}

func (expr *exprFileRatioBucket) bucketType() bucketType { return fileRatioBucket }

func (expr *exprFileRatioBucket) name() string {
	return "file-ratio-bucket-" + strconv.FormatUint(uint64(expr.prefix()), 10)
}

func (expr *exprFileRatioBucket) match(ctx requestCtx, request *dto.Request) bool {
	// Query file size index
	size, ok := expr.index.GetSize(unsafe.Slice(unsafe.StringData(request.URL), len(request.URL)))
	if !ok || size == 0 {
		return false // Impossible to track
	}
	fsize := float64(size)

	var buf fileRatioBucketBuf
	var bkt fileRatioBucketPayload

	keyBuffer := expr.keyBufferPool.Get()
	defer expr.keyBufferPool.Put(keyBuffer)
	keyBuffer = keyBuffer[:0]

	keyClientAddr := request.Client.As16()
	keyBuffer = append(keyBuffer, expr.cacheKeyPrefix)
	keyBuffer = append(keyBuffer, keyClientAddr[:]...)
	keyBuffer = append(keyBuffer, request.URL...)

	var timeDelta int64
	newBuf, ok := expr.cache.HasGet(buf[:], keyBuffer)
	if ok {
		bkt.read(newBuf)
		timeDelta = request.Time.Unix() - bkt.lastUpdate
	} else {
		bkt.lastUpdate = request.Time.Unix()
		timeDelta = 0
	}
	bkt.byteCount += request.Sent

	if timeDelta > 0 {
		bkt.byteCount = max(0, bkt.byteCount-int64(expr.leak*float64(size*timeDelta)))
		bkt.lastUpdate = request.Time.Unix()
	}

	bkt.write(newBuf)
	expr.cache.Set(keyBuffer[:], newBuf)

	if bkt.byteCount > int64(expr.volume*fsize) {
		ctx.kv[ctxKeyBanReason] = banReasonFileRatioOverflow
		ctx.kv[ctxKeyBanThreshold] = math.Float64bits(expr.volume)
		ctx.kv[ctxKeyBanValue] = math.Float64bits(float64(bkt.byteCount) / fsize)
		return true
	}
	return false
}

func (cb *chainBuilder) buildExprFileRatioBucket(value any) (exprBucket, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expression expects a string, got %T", value)
	}

	args := strings.Split(str, ",")
	if len(args) != 2 {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expression expects 2 arguments, got %d", len(args))
	}

	leak, err := strconv.ParseFloat(args[0], 64)
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expects float leak, got %s", args[0])
	}

	if leak < 0 {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expects non-negative leak, got %f", leak)
	}

	volume, err := strconv.ParseFloat(args[1], 64)
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expects float volume, got %s", args[1])
	}

	if volume < 0 {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expects non-negative volume, got %f", volume)
	}

	bc, err := cb.newBucketCommon()
	if err != nil {
		return nil, err
	}

	return &exprFileRatioBucket{
		bucketCommon: bc,
		leak:         leak,
		volume:       volume,
	}, nil
}
