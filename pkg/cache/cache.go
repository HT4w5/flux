package cache

import (
	"errors"
	"iter"
	"time"
)

var (
	ErrEntryNotFound = errors.New("entry not found")
)

type CacheEntry struct {
	LastUpdate int64
	Value      uint64
}

// Cache is used by engine bucket expressions
type Cache interface {
	Get(bucket string, key string) (entry CacheEntry, ok bool)
	Set(bucket string, key string, entry CacheEntry, ttl time.Duration)
	Iterator(bucket string) iter.Seq2[string, CacheEntry]
}
