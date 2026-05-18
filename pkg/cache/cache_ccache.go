package cache

import (
	"iter"
	"sync/atomic"
	"time"

	"github.com/karlseguin/ccache/v3"
)

type CCacheCache struct {
	cache *ccache.LayeredCache[CacheEntry]

	// Stats
	gets   atomic.Int64
	sets   atomic.Int64
	misses atomic.Int64
}

func NewCCacheCache(maxEntries int64) *CCacheCache {
	cache := ccache.Layered(ccache.Configure[CacheEntry]().MaxSize(maxEntries).GetsPerPromote(1))
	return &CCacheCache{
		cache: cache,
	}
}

func (c *CCacheCache) Get(bucket string, key string) (entry CacheEntry, ok bool) {
	c.gets.Add(1)
	if item := c.cache.Get(bucket, key); item == nil || item.Expired() {
		c.misses.Add(1)
		return
	} else {
		entry = item.Value()
		ok = true
		return
	}
}

func (c *CCacheCache) Set(bucket string, key string, entry CacheEntry, ttl time.Duration) {
	c.sets.Add(1)
	c.cache.Set(bucket, key, entry, ttl)
}

func (c *CCacheCache) Iterator(bucket string) iter.Seq2[string, CacheEntry] {
	return func(yield func(string, CacheEntry) bool) {
		c.cache.ForEachFunc(bucket, func(key string, item *ccache.Item[CacheEntry]) bool {
			if item.Expired() {
				return true
			}
			return yield(key, item.Value())
		})
	}
}

func (c *CCacheCache) Statistics() Statistics {
	return Statistics{
		Gets:      c.gets.Load(),
		Sets:      c.sets.Load(),
		Misses:    c.misses.Load(),
		Evictions: int64(c.cache.GetDropped()),
		Size:      c.cache.GetSize(),
	}
}
