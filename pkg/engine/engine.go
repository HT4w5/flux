package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HT4w5/cache"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/pool"
)

// engine states
const (
	engineNotStarted int32 = iota
	engineRunning
	engineStopping
	engineStopped
)

type Jail interface {
	Add(ctx context.Context, b *dto.BanRecord) error
}

type FileSizeIndex interface {
	GetSize(path []byte) (int64, bool)
}

type RuleEngine struct {
	jail          Jail
	cache         *cache.Cache
	fileSizeIndex FileSizeIndex
	logger        *slog.Logger
	ctxKVPool     *pool.MapPool[int, uint64]
	keyBufferPool *pool.BytePool
	main          chain
	requestChan   chan dto.Request // engine-owned channel

	bucketMap      map[bucketID]exprBucket
	requestBufSize int

	state atomic.Int32 // engineNotStarted / engineRunning / engineStopping / engineStopped

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
func WithJail(j Jail) Option {
	return func(re *RuleEngine) {
		if j == nil {
			panic("engine: WithJail requires a non-nil jail")
		}
		re.jail = j
	}
}

// WithFileSizeIndex sets the FileSizeIndex for the RuleEngine.
// Must not be nil.
func WithFileSizeIndex(fileSizeIndex FileSizeIndex) Option {
	return func(re *RuleEngine) {
		if fileSizeIndex == nil {
			panic("engine: WithFileSizeIndex requires a non-nil FileSizeIndex")
		}
		re.fileSizeIndex = fileSizeIndex
	}
}

// WithLogger sets the logger for the RuleEngine.
// Must not be nil.
func WithLogger(logger *slog.Logger) Option {
	return func(re *RuleEngine) {
		if logger == nil {
			panic("engine: WithLogger requires a non-nil logger")
		}
		re.logger = logger
	}
}

// WithNumWorkers sets the number of worker goroutines for the RuleEngine.
// Must be greater than 0.
func WithNumWorkers(num int) Option {
	return func(re *RuleEngine) {
		if num <= 0 {
			panic("engine: WithNumWorkers requires a positive number")
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

// WithBufferSize sets the capacity of the internal request channel.
// Defaults to 1024. A value of 0 creates an unbuffered channel.
func WithBufferSize(n int) Option {
	return func(re *RuleEngine) {
		if n < 0 {
			panic("engine: WithBufferSize requires a non-negative value")
		}
		re.requestBufSize = n
	}
}

func New(opts ...Option) *RuleEngine {
	re := &RuleEngine{
		logger:         slog.New(slog.DiscardHandler),
		ctxKVPool:      pool.NewMapPool[int, uint64](32),
		keyBufferPool:  pool.NewBytePool(128),
		maxCacheBytes:  200_000_000,
		requestBufSize: 1024,
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

	re.requestChan = make(chan dto.Request, re.requestBufSize)
	re.cache = cache.New(cache.WithSize(re.maxCacheBytes))

	return re
}

// Start builds chain and launches workers.
// Returns error on engine state mismatch or missing components.
func (re *RuleEngine) Start(chains []ChainConfig) error {
	if !re.state.CompareAndSwap(engineNotStarted, engineRunning) {
		return errors.New("engine: already started or shut down")
	}

	if re.jail == nil || re.fileSizeIndex == nil {
		re.state.Store(engineNotStarted)
		return errors.New("engine: required fields not set (jail, request channel, file size index)")
	}

	// Build chains
	cb := chainBuilder{
		re:            re,
		bucketMap:     make(map[bucketID]exprBucket),
		bucketCounter: 0,
	}
	main, err := cb.buildChains(chains)
	if err != nil {
		re.state.Store(engineNotStarted)
		re.logger.Error("Start: failed to build chains", "error", err)
		return err
	}

	re.main = main
	re.bucketMap = cb.bucketMap

	// Start workers
	re.logger.Debug("RuleEngine startup")
	wCtx, stop := context.WithCancel(context.Background())
	re.workers.stop = stop

	for range re.workers.num {
		re.workers.Go(func() { re.routineWorker(wCtx) })
	}

	return nil
}

func (re *RuleEngine) Shutdown() {
	re.ShutdownWithTimeout(0)
}

func (re *RuleEngine) ShutdownWithTimeout(waitTimeout time.Duration) {
	if !re.state.CompareAndSwap(engineRunning, engineStopping) {
		return
	}

	re.logger.Debug("RuleEngine shutdown")

	close(re.requestChan)

	if re.workers.stop != nil {
		re.workers.stop()
	}

	if waitTimeout > 0 {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), waitTimeout)
		defer waitCancel()
		done := make(chan struct{})
		go func() {
			re.workers.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-waitCtx.Done():
			re.logger.Warn("ShutdownWithTimeout: workers did not finish in time")
		}
	} else {
		re.workers.Wait()
	}

	re.workers.stop = nil

	if re.cache != nil {
		re.cache.Reset()
	}

	re.state.Store(engineStopped)
}

func (re *RuleEngine) routineWorker(ctx context.Context) {
	for request := range re.requestChan {
		re.handleRequest(ctx, &request)
	}
}

func (re *RuleEngine) handleRequest(ctx context.Context, request *dto.Request) {
	defer func() {
		if r := recover(); r != nil {
			re.logger.Error("routineWorker: panic recovered", "panic", r)
		}
	}()
	rctx := requestCtx{
		Context: ctx,
		logger:  re.logger,
		kv:      re.newCtxKV(),
	}
	re.main.traverse(rctx, request)
	re.ctxKVPool.Put(rctx.kv)
}

func (re *RuleEngine) SendChan() chan<- dto.Request {
	return re.requestChan
}

func (re *RuleEngine) GetStats() cache.Statistics {
	if re.state.Load() != engineRunning {
		return cache.Statistics{}
	}
	return re.cache.Statistics()
}
