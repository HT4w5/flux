package engine

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/HT4w5/flux/pkg/cache"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/docker/go-units"
)

// Bucket expressions

type exprBucket interface {
	match(ctx requestCtx, request *dto.Request) bool
	name() string
	typeName() string
	config() any
}

// --- Byte Bucket ---

type exprByteBucket struct {
	_name  string
	cache  cache.Cache
	leak   int64
	volume int64
	ttl    time.Duration
}

func (expr *exprByteBucket) name() string {
	return expr._name
}

func (expr *exprByteBucket) typeName() string {
	return "byte"
}

func (expr *exprByteBucket) config() any {
	return struct {
		Leak   string        `json:"leak"`
		Volume string        `json:"volume"`
		TTL    time.Duration `json:"ttl"`
	}{
		Leak:   units.HumanSize(float64(expr.leak)),
		Volume: units.HumanSize(float64(expr.volume)),
		TTL:    expr.ttl,
	}
}

func (expr *exprByteBucket) match(ctx requestCtx, request *dto.Request) bool {
	var timeDelta int64
	keyClientAddr := request.Client.As16()
	key := string(keyClientAddr[:])
	bkt, ok := expr.cache.Get(expr._name, key)
	if ok {
		timeDelta = request.Time - bkt.LastUpdate
	} else {
		bkt.LastUpdate = request.Time
		timeDelta = 0
	}
	bkt.Value += request.Sent

	if timeDelta > 0 {
		bkt.Value = max(0, bkt.Value-expr.leak*timeDelta)
		bkt.LastUpdate = request.Time
	}

	expr.cache.Set(expr._name, key, bkt, expr.ttl)

	if bkt.Value > expr.volume {
		ctx.kv[ctxKeyBanReason] = banReasonByteOverflow
		ctx.kv[ctxKeyBanThreshold] = uint64(expr.volume)
		ctx.kv[ctxKeyBanValue] = uint64(bkt.Value)
		return true
	}
	return false
}

func (cb *chainBuilder) buildExprByteBucket(value any) (exprBucket, error) {
	m, err := assertRootMap(value)
	if err != nil {
		return nil, fmt.Errorf("BYTE-BUCKET: %w", err)
	}

	name, err := assertString(m, "name")
	if err != nil {
		return nil, fmt.Errorf("BYTE-BUCKET: %w", err)
	}

	if _, exists := cb.bucketMap[name]; exists {
		return nil, fmt.Errorf("BYTE-BUCKET: duplicate bucket name %q", name)
	}

	leak, err := assertByteSize(m, "leak")
	if err != nil {
		return nil, fmt.Errorf("BYTE-BUCKET: %w", err)
	}
	if leak < 0 {
		return nil, fmt.Errorf("BYTE-BUCKET expects non-negative leak, got %d", leak)
	}

	volume, err := assertByteSize(m, "volume")
	if err != nil {
		return nil, fmt.Errorf("BYTE-BUCKET: %w", err)
	}
	if volume < 0 {
		return nil, fmt.Errorf("BYTE-BUCKET expects non-negative volume, got %d", volume)
	}

	return &exprByteBucket{
		_name:  name,
		cache:  cb.re.cache,
		leak:   leak,
		volume: volume,
		ttl:    ttl(leak, volume),
	}, nil
}

// --- Freq Bucket ---

type exprFreqBucket struct {
	_name  string
	cache  cache.Cache
	leak   int64
	volume int64
	ttl    time.Duration
}

func (expr *exprFreqBucket) name() string {
	return expr._name
}

func (expr *exprFreqBucket) typeName() string {
	return "freq"
}

func (expr *exprFreqBucket) config() any {
	return struct {
		Leak   int64         `json:"leak"`
		Volume int64         `json:"volume"`
		TTL    time.Duration `json:"ttl"`
	}{
		Leak:   expr.leak,
		Volume: expr.volume,
		TTL:    expr.ttl,
	}
}

func (expr *exprFreqBucket) match(ctx requestCtx, request *dto.Request) bool {
	var timeDelta int64
	keyClientAddr := request.Client.As16()
	key := string(keyClientAddr[:])
	bkt, ok := expr.cache.Get(expr._name, key)
	if ok {
		timeDelta = request.Time - bkt.LastUpdate
	} else {
		bkt.LastUpdate = request.Time
		timeDelta = 0
	}
	bkt.Value++

	if timeDelta > 0 {
		bkt.Value = max(0, bkt.Value-expr.leak*timeDelta)
		bkt.LastUpdate = request.Time
	}

	expr.cache.Set(expr._name, key, bkt, expr.ttl)

	if bkt.Value > expr.volume {
		ctx.kv[ctxKeyBanReason] = banReasonFreqOverflow
		ctx.kv[ctxKeyBanThreshold] = uint64(expr.volume)
		ctx.kv[ctxKeyBanValue] = uint64(bkt.Value)
		return true
	}
	return false
}

func (cb *chainBuilder) buildExprFreqBucket(value any) (exprBucket, error) {
	m, err := assertRootMap(value)
	if err != nil {
		return nil, fmt.Errorf("FREQ-BUCKET: %w", err)
	}

	name, err := assertString(m, "name")
	if err != nil {
		return nil, fmt.Errorf("FREQ-BUCKET: %w", err)
	}

	if _, exists := cb.bucketMap[name]; exists {
		return nil, fmt.Errorf("FREQ-BUCKET: duplicate bucket name %q", name)
	}

	leak, err := assertInt64(m, "leak")
	if err != nil {
		return nil, fmt.Errorf("FREQ-BUCKET: %w", err)
	}
	if leak < 0 {
		return nil, fmt.Errorf("FREQ-BUCKET expects non-negative leak, got %d", leak)
	}

	volume, err := assertInt64(m, "volume")
	if err != nil {
		return nil, fmt.Errorf("FREQ-BUCKET: %w", err)
	}
	if volume < 0 {
		return nil, fmt.Errorf("FREQ-BUCKET expects non-negative volume, got %d", volume)
	}

	return &exprFreqBucket{
		_name:  name,
		cache:  cb.re.cache,
		leak:   leak,
		volume: volume,
		ttl:    ttl(leak, volume),
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
	_name  string
	cache  cache.Cache
	volume volumeMethod
	index  FileSizeIndex
	leak   float64
}

func (expr *exprFileRatioBucket) name() string {
	return expr._name
}

func (expr *exprFileRatioBucket) typeName() string {
	return "file-ratio"
}

func (expr *exprFileRatioBucket) config() any {
	return struct {
		Leak         float64 `json:"leak"`
		VolumeMethod string  `json:"volume_method"`
	}{
		Leak:         expr.leak,
		VolumeMethod: expr.volume.name(),
	}
}

func (expr *exprFileRatioBucket) match(ctx requestCtx, request *dto.Request) bool {
	// Query file size index
	size, ok := expr.index.GetSize([]byte(request.URL))
	if !ok || size == 0 {
		return false // No size info, impossible to track
	}
	fsize := float64(size)

	var timeDelta int64
	keyClientAddr := request.Client.As16()
	key := string(keyClientAddr[:]) + request.URL
	bkt, ok := expr.cache.Get(expr._name, key)
	if ok {
		timeDelta = request.Time - bkt.LastUpdate
	} else {
		bkt.LastUpdate = request.Time
		timeDelta = 0
	}
	bkt.Value += request.Sent

	if timeDelta > 0 {
		if expr.leak != 0 {
			leakBytes := int64(expr.leak * float64(size) * float64(timeDelta))
			bkt.Value = max(0, bkt.Value-max(1, leakBytes)) // At least leak 1 byte if expr.leak is not zero
		}
		bkt.LastUpdate = request.Time
	}

	volume := expr.volume.volume(fsize)
	ttl := ttlFloat(expr.leak, volume)
	expr.cache.Set(expr._name, key, bkt, ttl)

	threshold := volume * fsize
	// Overflow guard
	if threshold > math.MaxInt64 {
		return false
	}

	if bkt.Value > int64(threshold) {
		ctx.kv[ctxKeyBanReason] = banReasonFileRatioOverflow
		ctx.kv[ctxKeyBanThreshold] = math.Float64bits(volume)
		ctx.kv[ctxKeyBanValue] = math.Float64bits(float64(bkt.Value) / fsize)
		return true
	}
	return false
}

func (cb *chainBuilder) buildExprFileRatioBucket(value any) (exprBucket, error) {
	m, err := assertRootMap(value)
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET: %w", err)
	}

	name, err := assertString(m, "name")
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET: %w", err)
	}

	if _, exists := cb.bucketMap[name]; exists {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET: duplicate bucket name %q", name)
	}

	leak, err := assertFloat64(m, "leak")
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET: %w", err)
	}

	volMap, err := assertStringMap(m, "volume")
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET: %w", err)
	}

	volMethod, err := assertString(volMap, "method")
	if err != nil {
		return nil, fmt.Errorf("FILE-RATIO-BUCKET volume: %w", err)
	}

	var volume volumeMethod
	switch volMethod {
	case "constant":
		v, err := assertFloat64(volMap, "volume")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume constant: %w", err)
		}
		volume = constantVolume{
			_name:   fmt.Sprintf("constant,volume=%f", v),
			_volume: v,
		}

	case "clamped-linear":
		intercept, err := assertFloat64(volMap, "intercept")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume clamped-linear: %w", err)
		}
		slope, err := assertFloat64(volMap, "slope")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume clamped-linear: %w", err)
		}
		minV, err := assertFloat64(volMap, "min")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume clamped-linear: %w", err)
		}
		maxV, err := assertFloat64(volMap, "max")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume clamped-linear: %w", err)
		}
		if maxV < minV {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume clamped-linear: max must be >= min")
		}
		volume = clampedLinearVolume{
			_name:     fmt.Sprintf("clamped-linear,intercept=%f,slope=%f,min=%f,max=%f", intercept, slope, minV, maxV),
			intercept: intercept,
			slope:     slope,
			min:       minV,
			max:       maxV,
		}

	case "inverse-square":
		base, err := assertFloat64(volMap, "base")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume inverse-square: %w", err)
		}
		pivotRaw, ok := volMap["pivot"]
		if !ok {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume inverse-square: missing field \"pivot\"")
		}
		pivot, err := parseExprFloatByteSize(pivotRaw)
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume inverse-square: invalid pivot: %w", err)
		}
		volume = inverseSquareVolume{
			_name:        fmt.Sprintf("inverse-square,base=%f,pivot=%s", base, units.HumanSize(pivot)),
			base:         base,
			pivotSquared: pivot * pivot,
		}

	case "step":
		thresholdRaw, ok := volMap["threshold"]
		if !ok {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume step: missing field \"threshold\"")
		}
		threshold, err := parseExprFloatByteSize(thresholdRaw)
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume step: invalid threshold: %w", err)
		}
		volumeLow, err := assertFloat64(volMap, "volume_low")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume step: %w", err)
		}
		volumeHigh, err := assertFloat64(volMap, "volume_high")
		if err != nil {
			return nil, fmt.Errorf("FILE-RATIO-BUCKET volume step: %w", err)
		}
		volume = stepVolume{
			_name:      fmt.Sprintf("step,threshold=%s,volume_low=%f,volume_high=%f", units.HumanSize(threshold), volumeLow, volumeHigh),
			threshold:  threshold,
			volumeLow:  volumeLow,
			volumeHigh: volumeHigh,
		}

	default:
		return nil, fmt.Errorf("FILE-RATIO-BUCKET: unknown volume method %q", volMethod)
	}

	return &exprFileRatioBucket{
		_name:  name,
		cache:  cb.re.cache,
		leak:   leak,
		volume: volume,
		index:  cb.re.fileSizeIndex,
	}, nil
}

// Used when leak is zero
const defaultTTL = time.Hour

// Maximum number of seconds that can be represented as time.Duration
const maxDurationSecs = int64(math.MaxInt64 / int64(time.Second))

func ttl(leak, volume int64) time.Duration {
	if leak <= 0 {
		return defaultTTL
	}
	secs := volume / leak
	// Avoids overflow
	if secs > maxDurationSecs {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs) * time.Second
}

func ttlFloat(leak, volume float64) time.Duration {
	if leak <= 0 {
		return defaultTTL
	}
	secs := volume / leak
	if secs > float64(maxDurationSecs) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs) * time.Second
}

// Assert helpers

func assertString(m map[string]any, fieldName string) (string, error) {
	fa, ok := m[fieldName]
	if !ok {
		return "", fmt.Errorf("missing field %q", fieldName)
	}

	f, ok := fa.(string)
	if !ok {
		return "", fmt.Errorf("expected string %s, got %T %v", fieldName, fa, fa)
	}

	return f, nil
}

func assertByteSize(m map[string]any, fieldName string) (int64, error) {
	fa, ok := m[fieldName]
	if !ok {
		return 0, fmt.Errorf("missing field %q", fieldName)
	}

	switch v := fa.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case uint64:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		n, err := units.FromHumanSize(v)
		if err != nil {
			n, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("expected byte size %s, got %q", fieldName, v)
			}
		}
		return n, nil
	default:
		return 0, fmt.Errorf("expected byte size %s, got %T %v", fieldName, fa, fa)
	}
}

func assertInt64(m map[string]any, fieldName string) (int64, error) {
	fa, ok := m[fieldName]
	if !ok {
		return 0, fmt.Errorf("missing field %q", fieldName)
	}

	switch v := fa.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case uint64:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("expected integer %s, got %q", fieldName, v)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("expected integer %s, got %T %v", fieldName, fa, fa)
	}
}

func assertFloat64(m map[string]any, fieldName string) (float64, error) {
	fa, ok := m[fieldName]
	if !ok {
		return 0, fmt.Errorf("missing field %q", fieldName)
	}

	switch v := fa.(type) {
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	case float64:
		return v, nil
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("expected float %s, got %q", fieldName, v)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("expected float %s, got %T %v", fieldName, fa, fa)
	}
}

func assertStringMap(m map[string]any, fieldName string) (map[string]any, error) {
	fa, ok := m[fieldName]
	if !ok {
		return nil, fmt.Errorf("missing field %q", fieldName)
	}

	sm, ok := fa.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected map %s, got %T %v", fieldName, fa, fa)
	}

	return sm, nil
}

func assertRootMap(value any) (map[string]any, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a map, got %T", value)
	}
	return m, nil
}
