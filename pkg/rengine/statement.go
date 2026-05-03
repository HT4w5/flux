package rengine

import (
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/docker/go-units"
)

type statement interface {
	execute(ctx requestCtx, request *dto.Request) (end bool)
}

type stmtStop struct{}

func (*stmtStop) execute(ctx requestCtx, request *dto.Request) (end bool) { return true }

type stmtContinue struct{}

func (*stmtContinue) execute(ctx requestCtx, request *dto.Request) (end bool) { return false }

type stmtGoto struct {
	target chain
}

func (stmt *stmtGoto) execute(ctx requestCtx, request *dto.Request) (end bool) {
	stmt.target.traverse(ctx, request)
	return true
}

func buildStmtGoto(chainMap map[string]chain, value any) (statement, error) {
	chainName, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("GOTO statement expects a string, got %T", value)
	}
	chain, ok := chainMap[chainName]
	if !ok {
		return nil, fmt.Errorf("GOTO statement targets non-existent chain: %s", chainName)
	}

	return &stmtJump{
		target: chain,
	}, nil
}

type stmtJump struct {
	target chain
}

func (stmt *stmtJump) execute(ctx requestCtx, request *dto.Request) (end bool) {
	stmt.target.traverse(ctx, request)
	return false
}

func buildStmtJump(chainMap map[string]chain, value any) (statement, error) {
	chainName, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("JUMP statement expects a string, got %T", value)
	}
	chain, ok := chainMap[chainName]
	if !ok {
		return nil, fmt.Errorf("JUMP statement targets non-existent chain: %s", chainName)
	}

	return &stmtJump{
		target: chain,
	}, nil
}

type stmtLog struct {
	prefix string
	level  slog.Level
}

func (stmt *stmtLog) execute(ctx requestCtx, request *dto.Request) (end bool) {
	ctx.logger.Log(ctx, stmt.level, stmt.prefix+request.String())
	return false
}

func buildStmtLog(value any) (statement, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("LOG statement expects a string, got %T", value)
	}

	args := strings.Split(str, ",")
	if len(args) != 2 {
		return nil, fmt.Errorf("LOG statement expects 2 arguments, got %d", len(args))
	}

	var level slog.Level
	switch strings.ToLower(args[0]) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("LOG statment got invalid log level: %s", args[0])
	}

	return &stmtLog{
		level:  level,
		prefix: args[1],
	}, nil
}

const (
	banReasonUnknown uint64 = iota
	banReasonByteOverflow
	banReasonFreqOverflow
	banReasonFileRatioOverflow
)

type stmtBan struct {
	re       *RuleEngine
	duration time.Duration
}

func (stmt *stmtBan) execute(ctx requestCtx, request *dto.Request) (end bool) {
	if err := stmt.re.jail.Add(ctx, &dto.BanRecord{
		Addr:      request.Client,
		ExpiresAt: time.Now().Add(stmt.duration),
		Blame:     buildBanBlame(ctx, request),
	}); err != nil {
		ctx.logger.Error("failed to add ban to jail", "error", err)
	}
	return true
}

func buildBanBlame(ctx requestCtx, request *dto.Request) string {
	reason := ctx.kv[ctxKeyBanReason]
	thresh := ctx.kv[ctxKeyBanThreshold]
	value := ctx.kv[ctxKeyBanValue]
	switch reason {
	case banReasonByteOverflow:
		return "sent byte overflow; threshold " + units.HumanSize(float64(thresh)) + ", got " + units.HumanSize(float64(value))
	case banReasonFreqOverflow:
		return "request frequency overflow; threshold " + strconv.FormatInt(int64(thresh), 10) + ", got " + strconv.FormatInt(int64(value), 10)
	case banReasonFileRatioOverflow:
		return "file ratio overflow for " + request.URL + " ; threshold " + strconv.FormatFloat(math.Float64frombits(thresh), 'f', 2, 64) + ", got " + strconv.FormatFloat(math.Float64frombits(value), 'f', 2, 64)
	case banReasonUnknown:
		fallthrough
	default:
		return "unknown ban reason " + strconv.FormatInt(int64(reason), 10)
	}
}

func (cb *chainBuilder) buildStmtBan(value any) (statement, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("BAN statement expects a string, got %T", value)
	}

	du, err := time.ParseDuration(str)
	if err != nil {
		return nil, fmt.Errorf("BAN statement got invalid duration: %s", str)
	}

	return &stmtBan{
		re:       cb.re,
		duration: du,
	}, nil
}
