package rengine

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/HT4w5/cache"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
	"github.com/HT4w5/flux/pkg/pool"
)

type RuleEngine struct {
	jail          jail.Jail
	cache         *cache.Cache
	fileSizeIndex *index.FileSizeIndex
	logger        *slog.Logger
	ctxKVPool     *pool.MapPool[int, uint64]
	keyBufferPool *pool.BytePool
	main          chain
	requestChan   <-chan dto.Request

	bucketMap map[byte]exprBucket

	workers struct {
		stop context.CancelFunc
		sync.WaitGroup
		num int
	}

	maxCacheBytes uint64
}

type Option func(*RuleEngine)

// WithJail sets the Jail for the RuleEngine.
// Must not be nil.
func WithJail(j jail.Jail) Option {
	return func(re *RuleEngine) {
		if j == nil {
			panic("rengine: WithJail requires a non-nil jail")
		}
		re.jail = j
	}
}

// WithFileSizeIndex sets the FileSizeIndex for the RuleEngine.
// Must not be nil.
func WithFileSizeIndex(fileSizeIndex *index.FileSizeIndex) Option {
	return func(re *RuleEngine) {
		if fileSizeIndex == nil {
			panic("rengine: WithFileSizeIndex requires a non-nil FileSizeIndex")
		}
		re.fileSizeIndex = fileSizeIndex
	}
}

// WithLogger sets the logger for the RuleEngine.
// Must not be nil.
func WithLogger(logger *slog.Logger) Option {
	return func(re *RuleEngine) {
		if logger == nil {
			panic("rengine: WithLogger requires a non-nil logger")
		}
		re.logger = logger
	}
}

// WithNumWorkers sets the number of worker goroutines for the RuleEngine.
// Must be greater than 0.
func WithNumWorkers(num int) Option {
	return func(re *RuleEngine) {
		if num <= 0 {
			panic("rengine: WithNumWorkers requires a positive number")
		}
		re.workers.num = num
	}
}

// WithMaxCacheBytes sets the max cache size in bytes.
func WithMaxCacheBytes(maxCacheBytes uint64) Option {
	return func(re *RuleEngine) {
		re.maxCacheBytes = maxCacheBytes
	}
}

// WithRequestChan sets the request channel for the RuleEngine.
// Must not be nil.
func WithRequestChan(ch <-chan dto.Request) Option {
	return func(re *RuleEngine) {
		if ch == nil {
			panic("rengine: WithRequestChan requires a non-nil channel")
		}
		re.requestChan = ch
	}
}

func New(opts ...Option) *RuleEngine {
	re := &RuleEngine{
		logger:        slog.New(slog.DiscardHandler),
		ctxKVPool:     pool.NewMapPool[int, uint64](32),
		keyBufferPool: pool.NewBytePool(128),
		maxCacheBytes: 200_000_000,
		workers: struct {
			stop context.CancelFunc
			sync.WaitGroup
			num int
		}{
			num: 8,
		},
	}

	for _, opt := range opts {
		opt(re)
	}

	re.cache = cache.New(cache.WithSize(re.maxCacheBytes))

	return re
}

func (re *RuleEngine) StartOrReload(chains []ChainConfig) error {
	if re.jail == nil || re.requestChan == nil || re.fileSizeIndex == nil {
		return errors.New("required fields not set")
	}

	// Build chains
	cb := chainBuilder{
		re:            re,
		bucketMap:     make(map[byte]exprBucket),
		bucketCounter: 0,
	}
	main, err := cb.buildChains(chains)
	if err != nil {
		re.logger.Error("StartOrReload: failed to build chains", "error", err)
		return err
	}

	// Shutdown previous
	re.Shutdown()
	re.main = main
	re.bucketMap = cb.bucketMap

	// Start new
	re.logger.Debug("RuleEngine startup")
	wCtx, stop := context.WithCancel(context.Background())
	re.workers.stop = stop

	for range re.workers.num {
		re.workers.Go(func() { re.routineWorker(wCtx) })
	}

	return nil
}

func (re *RuleEngine) Shutdown() {
	re.logger.Debug("RuleEngine shutdown")
	if re.workers.stop != nil {
		re.workers.stop()
		re.workers.Wait()
	}

	if re.cache != nil {
		re.cache.Reset()
	}
}

func (re *RuleEngine) routineWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-re.requestChan:
			re.handleRequest(ctx, &request)
		}
	}
}

func (re *RuleEngine) handleRequest(ctx context.Context, request *dto.Request) {
	re.main.traverse(re.newRequestCtx(ctx), request)
}

func (re *RuleEngine) GetStats() cache.Statistics {
	return re.cache.Statistics()
}
