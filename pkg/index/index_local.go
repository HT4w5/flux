package index

import (
	"context"
	"errors"
	"os"
	"path"

	"github.com/HT4w5/flux/pkg/trie"
)

// LocalDriver reads file size information from local filesystem.
type LocalDriver struct {
	trie trie.PrefixTrie[string]
}

func NewLocalDriver(routes map[string]string) *LocalDriver {
	tb := trie.NewPrefixTrieBuilder[string]()

	for k, v := range routes {
		tb.Add(k, v)
	}

	return &LocalDriver{
		trie: tb.Build(),
	}
}

func (d *LocalDriver) Query(ctx context.Context, url string) (int64, error) {
	url = path.Clean(url)
	if url[0] != '/' {
		return 0, ErrBadURL
	}
	newPrefix, prefixLen, ok := d.trie.LongestPrefixMatchWithLen(url)
	if !ok {
		return notFound, nil
	}

	return d.queryFilesystem(newPrefix + url[prefixLen:])
}

func (d *LocalDriver) queryFilesystem(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return notFound, nil
		}
		return 0, err
	}

	if info.IsDir() {
		return notFound, nil
	}

	return info.Size(), nil
}
