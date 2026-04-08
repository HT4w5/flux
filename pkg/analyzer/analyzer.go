package analyzer

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/HT4w5/cache"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/filter"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
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

	// Performance settings
	NumWorkers int
	MaxBytes   int64

	// Filter settings
	FilterMode FilterMode
}

type Analyzer struct {
	ingressFilter          filter.FilterRule
	clientBucketFilter     filter.FilterRule
	clientPathBucketFilter filter.FilterRule
	jail                   jail.Jail
	workerStop             context.CancelFunc
	workerWg               sync.WaitGroup
	bucketCache            *cache.Cache
	keyBufferPool          *pool.BytePool
	index                  *index.FileSizeIndex
	logger                 *slog.Logger
	requestChan            <-chan dto.Request
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
			NumWorkers:           8,
			MaxBytes:             2 * units.GB,
			FilterMode:           Blacklist,
		},
		// Other stuff
		keyBufferPool:          pool.NewBytePool(128),
		logger:                 slog.New(slog.DiscardHandler),
		ingressFilter:          filter.None{},
		clientBucketFilter:     filter.All{},
		clientPathBucketFilter: filter.All{},
	}

	for _, opt := range opts {
		opt(a)
	}

	// Create cache
	a.bucketCache = cache.New(cache.WithSize(uint64(a.config.MaxBytes)))

	return a
}

func (a *Analyzer) Start() {
	// Start workers
	ctx, stop := context.WithCancel(context.Background())
	a.workerStop = stop
	for i := range a.config.NumWorkers {
		a.workerWg.Go(func() { a.worker(ctx, i) })
	}
}

func (a *Analyzer) Shutdown() {
	a.logger.Info("analyzer shutdown")
	a.workerStop()
	a.workerWg.Wait()
	a.bucketCache.Reset()
}

func (a *Analyzer) worker(ctx context.Context, id int) {
	a.logger.Info("worker started", "id", id)
	for {
		select {
		case <-ctx.Done():
			a.logger.Info("worker exit", "id", id)
			return
		case request := <-a.requestChan:
			if a.ingressFilter.Match(&request) != bool(a.config.FilterMode) {
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

// WithRequestChan sets the ingress request channel for Analyzer.
func WithRequestChan(requestChan <-chan dto.Request) func(*Analyzer) {
	return func(a *Analyzer) {
		a.requestChan = requestChan
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

// WithConfig sets configuration for Analyzer.
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

// WithIngressFilter sets the ingress request filter for Analyzer.
func WithIngressFilter(f filter.FilterRule) func(*Analyzer) {
	return func(a *Analyzer) {
		a.ingressFilter = f
	}
}

// WithClientBucketFilter sets the client bucket request filter for Analyzer.
func WithClientBucketFilter(f filter.FilterRule) func(*Analyzer) {
	return func(a *Analyzer) {
		a.clientBucketFilter = f
	}
}

// WithClientPathBucketFilter sets the client-path bucket request filter for Analyzer.
func WithClientPathBucketFilter(f filter.FilterRule) func(*Analyzer) {
	return func(a *Analyzer) {
		a.clientPathBucketFilter = f
	}
}
