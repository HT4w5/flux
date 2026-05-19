package index

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/docker/go-units"
	"github.com/karlseguin/ccache/v3"
)

const (
	notFound int64 = -1
)

var (
	ErrNotFound = errors.New("not found")
	ErrBadURL   = errors.New("bad url")
)

type Driver interface {
	// Query should return (notFound, nil) when file size info is not available
	// for caching.
	Query(ctx context.Context, url string) (size int64, err error)
}

// Index provides file size information for file ratio buckets
type Index struct {
	driver Driver
	cache  *ccache.Cache[int64]
	logger *slog.Logger

	// Stats
	queries atomic.Int64
	misses  atomic.Int64

	// Config
	ttl             time.Duration
	maxCacheEntries int64
}

type Option func(*Index)

func New(opts ...Option) *Index {
	idx := &Index{
		logger:          slog.New(slog.DiscardHandler),
		maxCacheEntries: 1024,
		ttl:             6 * time.Hour,
	}

	for _, opt := range opts {
		opt(idx)
	}

	idx.cache = ccache.New(ccache.Configure[int64]().MaxSize(idx.maxCacheEntries))

	return idx
}

func WithMaxCacheEntries(maxCacheEntries int64) Option {
	return func(i *Index) {
		i.maxCacheEntries = maxCacheEntries
	}
}

func WithDriver(driver Driver) Option {
	return func(i *Index) {
		i.driver = driver
	}
}

func WithTTL(ttl time.Duration) Option {
	return func(i *Index) {
		i.ttl = ttl
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(i *Index) {
		i.logger = logger
	}
}

func (idx *Index) Query(ctx context.Context, url string) (int64, error) {
	idx.queries.Add(1)
	if item, err := idx.cache.Fetch(url, idx.ttl, func() (int64, error) {
		idx.misses.Add(1)
		return idx.driver.Query(ctx, url)
	}); err != nil {
		return 0, err
	} else {
		v := item.Value()
		if v == notFound {
			return v, ErrNotFound
		}
		return v, nil
	}
}

type SizeEntry struct {
	Path string `json:"path"`
	Size string `json:"size"`
}

func (idx *Index) Iterator() iter.Seq[SizeEntry] {
	return func(yield func(SizeEntry) bool) {
		idx.cache.ForEachFunc(func(key string, item *ccache.Item[int64]) bool {
			if item.Expired() {
				return true
			}
			v := item.Value()
			e := SizeEntry{
				Path: key,
			}
			if v < 0 {
				e.Size = strconv.FormatInt(v, 10)
			} else {
				e.Size = units.HumanSize(float64(v))
			}
			return yield(e)
		})
	}
}

type Statistics struct {
	Queries   int64 `json:"queries"`
	Misses    int64 `json:"misses"`
	Evictions int64 `json:"evictions"`
	Size      int64 `json:"size"`
}

func (idx *Index) Statistics() Statistics {
	return Statistics{
		Queries:   idx.queries.Load(),
		Misses:    idx.misses.Load(),
		Evictions: int64(idx.cache.GetDropped()),
		Size:      idx.cache.GetSize(),
	}
}
