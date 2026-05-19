package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HT4w5/flux/pkg/cache"
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

type Index interface {
	Query(ctx context.Context, url string) (int64, error)
}

type RuleEngine struct {
	jail        Jail
	cache       cache.Cache
	index       Index
	logger      *slog.Logger
	ctxKVPool   *pool.MapPool[int, uint64]
	main        chain
	requestChan chan dto.Request // engine-owned channel

	bucketMap      map[string]exprBucket
	requestBufSize int

	state atomic.Int32 // engineNotStarted / engineRunning / engineStopping / engineStopped

	workers struct {
		stop context.CancelFunc
		sync.WaitGroup
		num int
	}
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

// WithIndex sets the Index for the RuleEngine.
// Must not be nil.
func WithIndex(index Index) Option {
	return func(re *RuleEngine) {
		if index == nil {
			panic("engine: WithIndex requires a non-nil Index")
		}
		re.index = index
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

// WithCache sets the Cache for the RuleEngine.
// Must not be nil.
func WithCache(c cache.Cache) Option {
	return func(re *RuleEngine) {
		if c == nil {
			panic("engine: WithCache requires a non-nil cache")
		}
		re.cache = c
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

	return re
}

// Start builds chain and launches workers.
// Returns error on engine state mismatch or missing components.
func (re *RuleEngine) Start(chains []ChainConfig) error {
	if !re.state.CompareAndSwap(engineNotStarted, engineRunning) {
		return errors.New("engine: already started or shut down")
	}

	if re.jail == nil || re.index == nil || re.cache == nil {
		re.state.Store(engineNotStarted)
		return errors.New("engine: required fields not set (jail, cache, file size index)")
	}

	// Build chains
	cb := chainBuilder{
		re:        re,
		bucketMap: make(map[string]exprBucket),
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
