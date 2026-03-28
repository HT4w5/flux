package analyzer

import (
	"context"
	"log/slog"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
	"github.com/HT4w5/flux/pkg/logsrc"
	"github.com/HT4w5/flux/pkg/pool"
	"github.com/VictoriaMetrics/fastcache"
	"github.com/docker/go-units"
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
	FileRatioLeak        int64
	FileRatioVolume      int64
	FileRatioBanDuration time.Duration

	// IP ban prefix lengths
	IPv4BanPrefixLen int
	IPv6BanPrefixLen int

	// Performance settings
	NumWorkers int
	MaxBytes   int64
}

type Analyzer struct {
	// Internal
	bucketCache   *fastcache.Cache
	keyBufferPool *pool.BytePool

	// External
	src    logsrc.LogSource
	index  *index.FileSizeIndex
	jail   jail.Jail
	logger *slog.Logger

	// Channels
	requestChan chan dto.Request

	// Config
	config Config
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
		},
		// Other stuff
		keyBufferPool: pool.NewBytePool(128),
		logger:        slog.New(slog.DiscardHandler),
	}

	for _, opt := range opts {
		opt(a)
	}

	a.bucketCache = fastcache.New(int(a.config.MaxBytes))
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
			a.updateClientBucket(ctx, &request)
			a.updateClientPathBucket(ctx, &request)
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
