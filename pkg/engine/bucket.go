package engine

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unsafe"

	"github.com/HT4w5/cache"
	"github.com/HT4w5/flux/pkg/dto"
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
	name() string
}

// --- Byte Bucket ---

type exprByteBucket struct {
	_name string
	bucketCommon
	leak   int64
	volume int64
}

func (expr *exprByteBucket) name() string {
	return expr._name
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
		newBuf = buf[:]
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
		_name:        strconv.FormatUint(uint64(bc.prefix()), 10) + "-byte",
		bucketCommon: bc,
		leak:         leak,
		volume:       volume,
	}, nil
}

// --- Freq Bucket ---

type exprFreqBucket struct {
	_name string
	bucketCommon
	leak   int64
	volume int64
}

func (expr *exprFreqBucket) name() string {
	return expr._name
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
		newBuf = buf[:]
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
		_name:        strconv.FormatUint(uint64(bc.prefix()), 10) + "-freq",
		bucketCommon: bc,
		leak:         leak,
		volume:       volume,
	}, nil
}

// --- File Ratio Bucket ---

type volumeMethod interface {
	volume(size float64) float64
	name() string
}

type constantVolume struct {
	_name   string
	_volume float64
}

func (m constantVolume) volume(size float64) float64 {
	return m._volume
}

func (m constantVolume) name() string {
	return m._name
}

type clampedLinearVolume struct {
	_name     string
	intercept float64
	slope     float64
	min       float64
	max       float64
}

func (m clampedLinearVolume) volume(size float64) float64 {
	return max(m.min, min(m.max, m.intercept+size*m.slope))
}

func (m clampedLinearVolume) name() string {
	return m._name
}

type inverseSquareVolume struct {
	_name        string
	base         float64
	pivotSquared float64
}

func (m inverseSquareVolume) volume(size float64) float64 {
	return m.base + m.pivotSquared/(size*size)
}

func (m inverseSquareVolume) name() string {
	return m._name
}

type stepVolume struct {
	_name      string
	threshold  float64
	volumeLow  float64
	volumeHigh float64
}

func (m stepVolume) volume(size float64) float64 {
	if size >= m.threshold {
		return m.volumeHigh
	} else {
		return m.volumeLow
	}
}

func (m stepVolume) name() string {
	return m._name
}

type exprFileRatioBucket struct {
	_name string
	index FileSizeIndex
	bucketCommon
	leak   float64
	volume volumeMethod
}

func (expr *exprFileRatioBucket) name() string {
	return expr._name
}

func (expr *exprFileRatioBucket) match(ctx requestCtx, request *dto.Request) bool {
	// Query file size index
	size, ok := expr.index.GetSize(unsafe.Slice(unsafe.StringData(request.URL), len(request.URL)))
	if !ok || size == 0 {
		return false // No size info, impossible to track
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
		newBuf = buf[:]
	}
	bkt.byteCount += request.Sent

	if timeDelta > 0 {
		if expr.leak != 0 {
			bkt.byteCount = max(0, bkt.byteCount-max(1, int64(expr.leak*float64(size*timeDelta)))) // At least leak 1 byte if expr.leak is not zero
		}
		bkt.lastUpdate = request.Time.Unix()
	}

	bkt.write(newBuf)
	expr.cache.Set(keyBuffer[:], newBuf)

	if bkt.byteCount > int64(expr.volume.volume(fsize)*fsize) {
		ctx.kv[ctxKeyBanReason] = banReasonFileRatioOverflow
		ctx.kv[ctxKeyBanThreshold] = math.Float64bits(expr.volume.volume(fsize))
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
	if len(args) < 2 {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expression expects at least 2 arguments, got %d", len(args))
	}

	leak, err := strconv.ParseFloat(args[0], 64)
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET expects float leak, got %s", args[0])
	}

	args = args[1:]

	var volume volumeMethod
	switch args[0] {
	case "constant":
		if len(args) != 2 {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"constant\" expects 1 arguments, got %d", len(args)-1)
		}
		vol := constantVolume{}

		var err error
		if vol._volume, err = strconv.ParseFloat(args[1], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"constant\" expects float volume, got %s", args[1])
		}
		vol._name = fmt.Sprintf("constant,volume=%f", vol._volume)
		volume = vol

	case "clamped-linear":
		if len(args) != 5 {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"clamped-linear\" expects 4 arguments, got %d", len(args)-1)
		}
		vol := clampedLinearVolume{}

		var err error
		if vol.intercept, err = strconv.ParseFloat(args[1], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"clamped-linear\" expects float intercept, got %s", args[1])
		}
		if vol.slope, err = strconv.ParseFloat(args[2], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"clamped-linear\" expects float slope, got %s", args[2])
		}
		if vol.min, err = strconv.ParseFloat(args[3], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"clamped-linear\" expects float min, got %s", args[3])
		}
		if vol.max, err = strconv.ParseFloat(args[4], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"clamped-linear\" expects float max, got %s", args[4])
		}
		if vol.max < vol.min {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"clamped-linear\" expects max >= min")
		}

		vol._name = fmt.Sprintf("clamped-linear,intercept=%f,slope=%f,min=%f,max=%f", vol.intercept, vol.slope, vol.min, vol.max)
		volume = vol

	case "inverse-square":
		if len(args) != 3 {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"inverse-square\" expects 2 arguments, got %d", len(args)-1)
		}
		vol := inverseSquareVolume{}

		var err error
		if vol.base, err = strconv.ParseFloat(args[1], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"inverse-square\" expects float base, got %s", args[1])
		}
		if vol.pivotSquared, err = parseExprFloatByteSize(args[2]); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"inverse-square\" expects byte size pivot, got %s", args[2])
		}
		vol._name = fmt.Sprintf("inverse-square,base=%f,pivot=%s", vol.base, units.HumanSize(vol.pivotSquared))
		vol.pivotSquared = vol.pivotSquared * vol.pivotSquared
		volume = vol

	case "step":
		if len(args) != 4 {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"step\" expects 3 arguments, got %d", len(args)-1)
		}
		vol := stepVolume{}

		var err error
		if vol.threshold, err = parseExprFloatByteSize(args[1]); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"step\" expects byte size threshold, got %s", args[1])
		}
		if vol.volumeLow, err = strconv.ParseFloat(args[2], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"step\" expects float volume_low, got %s", args[2])
		}
		if vol.volumeHigh, err = strconv.ParseFloat(args[3], 64); err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET: method \"step\" expects float volume_high, got %s", args[3])
		}
		vol._name = fmt.Sprintf("step,threshold=%s,volume_low=%f,volume_high=%f", units.HumanSize(vol.threshold), vol.volumeLow, vol.volumeHigh)
		volume = vol
	default:
		return nil, fmt.Errorf("FILE-RATIO-BUCKET: unknown volume method \"%s\"", args[0])
	}

	bc, err := cb.newBucketCommon()
	if err != nil {
		return nil, err
	}

	return &exprFileRatioBucket{
		_name:        strconv.FormatUint(uint64(bc.prefix()), 10) + "-file-ratio",
		index:        cb.re.fileSizeIndex,
		bucketCommon: bc,
		leak:         leak,
		volume:       volume,
	}, nil
}
