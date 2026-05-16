package cache

import (
	"iter"
	"time"

	"github.com/karlseguin/ccache/v3"
)

type CCacheCache struct {
	cache *ccache.LayeredCache[CacheEntry]
}

func NewCCacheCache(maxSize int64) *CCacheCache {
	cache := ccache.Layered(ccache.Configure[CacheEntry]().MaxSize(maxSize).GetsPerPromote(1))
	return &CCacheCache{
		cache: cache,
	}
}

func (c *CCacheCache) Get(bucket string, key string) (entry CacheEntry, ok bool) {
	if item := c.cache.Get(bucket, key); item == nil || item.Expired() {
		return
	} else {
		entry = item.Value()
		ok = true
		return
	}
}

func (c *CCacheCache) Set(bucket string, key string, entry CacheEntry, ttl time.Duration) {
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
