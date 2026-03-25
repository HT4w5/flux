package index

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/allegro/bigcache"
)

const (
	NonExistent   int64 = -1
	NoRoute       int64 = -2
	IsDir         int64 = -3
	InternalError int64 = -4
)

type FileSizeIndex struct {
	cache    *bigcache.BigCache
	logger   *slog.Logger
	routeMap map[string]string

	// Config
	ttl          time.Duration
	maxCacheSize int
}

// WithTTL sets the time-to-live for cache entries.
func WithTTL(ttl time.Duration) func(*FileSizeIndex) {
	return func(i *FileSizeIndex) {
		i.ttl = ttl
	}
}

// WithMaxCacheSize sets the maximum cache size in MB.
func WithMaxCacheSize(size int) func(*FileSizeIndex) {
	return func(i *FileSizeIndex) {
		i.maxCacheSize = size
	}
}

// WithRoute adds a single route mapping for file paths.
func WithRoute(tag, root string) func(*FileSizeIndex) {
	return func(i *FileSizeIndex) {
		i.routeMap[tag] = root
	}
}

func New(opts ...func(*FileSizeIndex)) (*FileSizeIndex, error) {
	i := &FileSizeIndex{
		ttl:          6 * time.Hour,
		maxCacheSize: 1024,
		routeMap:     make(map[string]string),
	}

	for _, opt := range opts {
		opt(i)
	}

	var err error
	i.cache, err = bigcache.NewBigCache(bigcache.Config{
		Shards:             1024,
		LifeWindow:         i.ttl,
		CleanWindow:        5 * time.Minute,
		MaxEntriesInWindow: 1000 * 10 * 60,
		MaxEntrySize:       500,
		Verbose:            false,
		HardMaxCacheSize:   i.maxCacheSize,
	})
	if err != nil {
		return nil, err
	}

	return i, nil
}

func (i *FileSizeIndex) GetSize(path string) (int64, bool) {
	cleanPath := strings.TrimPrefix(path, "/")
	first, rest, found := strings.Cut(cleanPath, "/")
	if !found {
		return NoRoute, false
	}

	// Query cache first
	if size, ok := i.queryCache(path); ok {
		return size, size >= 0
	}

	root, ok := i.routeMap[first]
	if !ok {
		return 0, false
	}

	size := i.queryFilesystem(filepath.Join(root, rest))

	// Update cache
	if err := i.updateCache(path, size); err != nil {
		i.logger.Error("failed to update cache", "error", err, "path", path)
	}

	return size, size >= 0
}

func (i *FileSizeIndex) queryCache(path string) (int64, bool) {
	b, err := i.cache.Get(path)
	if err != nil {
		return 0, false
	}

	var p cachePayload
	p.read(b)
	if p.expiresAt.Before(time.Now()) {
		return 0, false
	}

	return p.size, true
}

func (i *FileSizeIndex) updateCache(path string, size int64) error {
	b := cachePayload{
		size:      size,
		expiresAt: time.Now().Add(i.ttl),
	}
	var buf [16]byte
	b.write(buf[:])
	return i.cache.Set(path, buf[:])
}

func (i *FileSizeIndex) queryFilesystem(path string) int64 {
	info, err := os.Stat(path)
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
