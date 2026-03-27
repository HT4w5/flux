package index

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/HT4w5/flux/pkg/pool"
	"github.com/VictoriaMetrics/fastcache"
)

const (
	NonExistent   int64 = -1
	NoRoute       int64 = -2
	IsDir         int64 = -3
	InternalError int64 = -4
)

type FileSizeIndex struct {
	cache          *fastcache.Cache
	logger         *slog.Logger
	routeMap       map[string]string
	pathBufferPool *pool.BytePool

	// Config
	ttl      time.Duration
	maxBytes int
}

// WithTTL sets the time-to-live for cache entries.
func WithTTL(ttl time.Duration) func(*FileSizeIndex) {
	return func(i *FileSizeIndex) {
		i.ttl = ttl
	}
}

// WithmaxBytes sets the maximum cache size in MB.
func WithmaxBytes(size int) func(*FileSizeIndex) {
	return func(i *FileSizeIndex) {
		i.maxBytes = size
	}
}

// WithRoute adds a single route mapping for file paths.
// E.g., "alpine" -> "/data/alpine".
func WithRoute(tag, root string) func(*FileSizeIndex) {
	root = strings.TrimSuffix(root, "/")
	return func(i *FileSizeIndex) {
		i.routeMap[tag] = root
	}
}

func New(opts ...func(*FileSizeIndex)) *FileSizeIndex {
	i := &FileSizeIndex{
		ttl:            6 * time.Hour,
		maxBytes:       1024,
		routeMap:       make(map[string]string),
		pathBufferPool: pool.NewBytePool(128),
	}

	for _, opt := range opts {
		opt(i)
	}

	i.cache = fastcache.New(i.maxBytes)

	return i
}

func (i *FileSizeIndex) GetSize(path []byte) (int64, bool) {
	var trimmed []byte
	if path[0] == '/' {
		trimmed = path[1:]
	} else {
		trimmed = path
	}

	slashIdx := bytes.IndexByte(trimmed, '/')
	if slashIdx < 0 {
		return NoRoute, false
	}

	// Query cache first
	if size, ok := i.queryCache(path); ok {
		return size, size >= 0
	}

	first := unsafe.String(unsafe.SliceData(trimmed[:slashIdx]), slashIdx)

	root, ok := i.routeMap[first]
	if !ok {
		return 0, false
	}

	buffer := i.pathBufferPool.Get()
	defer i.pathBufferPool.Put(buffer)

	buffer = buffer[:0]
	buffer = append(buffer, root...)
	buffer = append(buffer, trimmed[slashIdx:]...)

	size := i.queryFilesystem(buffer)

	// Update cache
	if size != InternalError {
		i.updateCache(path, size)
	}

	return size, size >= 0
}

func (i *FileSizeIndex) queryCache(path []byte) (int64, bool) {
	var buf payloadBuf
	i.cache.Get(buf[:], path)

	var p cachePayload
	p.read(buf[:])
	if p.expiresAt.Before(time.Now()) {
		return 0, false
	}

	return p.size, true
}

func (i *FileSizeIndex) updateCache(path []byte, size int64) {
	b := cachePayload{
		size:      size,
		expiresAt: time.Now().Add(i.ttl),
	}
	var buf [16]byte
	b.write(buf[:])
	i.cache.Set(path, buf[:])
}

func (i *FileSizeIndex) queryFilesystem(path []byte) int64 {
	pathStr := unsafe.String(unsafe.SliceData(path), len(path))
	info, err := os.Stat(pathStr)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NonExistent
		}
		i.logger.Error("error reading file", "error", err, "path", path)
		return InternalError
	}

	if info.IsDir() {
		return IsDir
	}

	return info.Size()
}
