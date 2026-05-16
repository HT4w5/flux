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
	Value      int64
}

type Statistics struct {
	Gets   int64 `json:"gets"`
	Sets   int64 `json:"sets"`
	Misses int64 `json:"misses"`
	// Evictions due to memory pressure
	Evictions int64 `json:"evictions"`
	// Number of entries
	Size int64 `json:"size"`
}

// Cache is used by engine bucket expressions
type Cache interface {
	Get(bucket string, key string) (entry CacheEntry, ok bool)
	Set(bucket string, key string, entry CacheEntry, ttl time.Duration)
	Iterator(bucket string) iter.Seq2[string, CacheEntry]
	Statistics() Statistics
}
