package engine

import (
	"context"
	"log/slog"
)

const (
	ctxKeyBanReason int = iota
	ctxKeyBanThreshold
	ctxKeyBanValue
)

type requestCtx struct {
	context.Context
	logger *slog.Logger
	kv     map[int]uint64
}

func (re *RuleEngine) newCtxKV() map[int]uint64 {
	kv := re.ctxKVPool.Get()

	// Initial values
	kv[ctxKeyBanReason] = banReasonUnknown

	return kv
}
