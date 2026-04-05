package analyzer

import (
	"context"
	"log/slog"
	"time"

	"github.com/HT4w5/cache"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/filter"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
	"github.com/HT4w5/flux/pkg/logsrc"
	"github.com/HT4w5/flux/pkg/pool"
	"github.com/docker/go-units"
)

type FilterMode bool

const (
	Whitelist FilterMode = true
	Blacklist FilterMode = false
)

// Analyzer config
type Config struct {
	// Request rate limiting
	RequestLeak        int
	RequestVolume      int
	RequestBanDuration time.Duration

	// Byte rate limiting
	ByteLeak        int64
	ByteVolume      int64
	ByteBanDuration time.Duration

	// File ratio rate limiting
	FileRatioLeak        float64
	FileRatioVolume      float64
	FileRatioBanDuration time.Duration

	// IP ban prefix lengths
	IPv4BanPrefixLen int
	IPv6BanPrefixLen int

	// Performance settings
	NumWorkers int
	MaxBytes   int64

	// Filter settings
	FilterMode FilterMode
}

type Analyzer struct {
	filter                 filter.FilterRule
	clientBucketFilter     filter.FilterRule
	clientPathBucketFilter filter.FilterRule
	src                    logsrc.LogSource
	jail                   jail.Jail
	bucketCache            *cache.Cache
	keyBufferPool          *pool.BytePool
	index                  *index.FileSizeIndex
	logger                 *slog.Logger
	requestChan            chan dto.Request
	config                 Config
}

func New(opts ...func(*Analyzer)) *Analyzer {
	a := &Analyzer{
		// Config with default values
		config: Config{
			RequestLeak:          10,
			RequestVolume:        50,
			RequestBanDuration:   24 * time.Hour,
			ByteLeak:             40 * units.MB,
			ByteVolume:           20 * units.GB,
			ByteBanDuration:      24 * time.Hour,
			FileRatioLeak:        5,   // 5/1e5 files per second
			FileRatioVolume:      5e5, // 5 files
			FileRatioBanDuration: 7 * 24 * time.Hour,
			IPv4BanPrefixLen:     24,
			IPv6BanPrefixLen:     48,
			NumWorkers:           8,
			MaxBytes:             2 * units.GB,
			FilterMode:           Blacklist,
		},
		// Other stuff
		keyBufferPool:          pool.NewBytePool(128),
		logger:                 slog.New(slog.DiscardHandler),
		filter:                 filter.None{},
		clientBucketFilter:     filter.All{},
		clientPathBucketFilter: filter.All{},
	}

	for _, opt := range opts {
		opt(a)
	}

	a.bucketCache = cache.New(cache.WithSize(uint64(a.config.MaxBytes)))
	a.requestChan = make(chan dto.Request)

	return a
}

func (a *Analyzer) Start(ctx context.Context) {
	// Start log source
	a.src.Start(ctx, a.requestChan)

	// Start workers
	for i := range a.config.NumWorkers {
		go a.worker(i, ctx)
	}
}

func (a *Analyzer) worker(id int, ctx context.Context) {
	a.logger.Info("worker started", "id", id)
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("worker exit", "id", id)
			return
		case request := <-a.requestChan:
			if a.filter.Match(&request) != bool(a.config.FilterMode) {
				// Drop
				a.logger.Debug("request dropped by filter", "request", request)
				continue
			}

			if a.clientBucketFilter.Match(&request) {
				a.logger.Debug("request matched for client bucket", "request", request)
				a.updateClientBucket(ctx, &request)
			}
			if a.clientPathBucketFilter.Match(&request) {
				a.logger.Debug("request matched for client path bucket", "request", request)
				a.updateClientPathBucket(ctx, &request)
			}
		}
	}
}

// Options
// WithLogSource sets the log source for Analyzer.
func WithLogSource(src logsrc.LogSource) func(*Analyzer) {
	return func(a *Analyzer) {
		a.src = src
	}
}

// WithIndex sets the file size index for Analyzer.
func WithIndex(idx *index.FileSizeIndex) func(*Analyzer) {
	return func(a *Analyzer) {
		a.index = idx
	}
}

// WithLogger sets a custom logger for Analyzer.
func WithLogger(logger *slog.Logger) func(*Analyzer) {
	return func(a *Analyzer) {
		a.logger = logger
	}
}

// WithConfig sets the entire configuration for Analyzer.
func WithConfig(config Config) func(*Analyzer) {
	return func(a *Analyzer) {
		a.config = config
	}
}

// WithJail sets the jail implementation for Analyzer.
func WithJail(j jail.Jail) func(*Analyzer) {
	return func(a *Analyzer) {
		a.jail = j
	}
}

// WithFilter sets the log filter for Analyzer.
func WithFilter(f filter.FilterRule) func(*Analyzer) {
	return func(a *Analyzer) {
		a.filter = f
	}
}

// WithFilter sets the log filter for Analyzer.
func WithClientBucketFilter(f filter.FilterRule) func(*Analyzer) {
	return func(a *Analyzer) {
		a.clientBucketFilter = f
	}
}

// WithFilter sets the log filter for Analyzer.
func WithClientPathBucketFilter(f filter.FilterRule) func(*Analyzer) {
	return func(a *Analyzer) {
		a.clientPathBucketFilter = f
	}
}
