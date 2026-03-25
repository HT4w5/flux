package analyzer

import (
	"time"

	"github.com/HT4w5/flux/pkg/logsrc"
	"github.com/HT4w5/flux/pkg/output"
	"github.com/gaissmai/bart"
)

type triePayload struct {
	requestCount int
	fileCount    int
	lastUpdate   time.Time
}

type Analyzer struct {
	src logsrc.LogSource
	out *output.Output

	// Client trie
	trie *bart.Fast[triePayload]
}
