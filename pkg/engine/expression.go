package engine

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/trie"
	"github.com/docker/go-units"
	"go4.org/netipx"
)

type expression interface {
	match(ctx requestCtx, request *dto.Request) bool
}

// Logical expressions

type exprAll struct{}

func (a exprAll) match(ctx requestCtx, request *dto.Request) bool { return true }

type exprNone struct{}

func (n exprNone) match(ctx requestCtx, request *dto.Request) bool { return false }

type exprAnd []expression

func (a exprAnd) match(ctx requestCtx, request *dto.Request) bool {
	for _, rule := range a {
		if !rule.match(ctx, request) {
			return false
		}
	}
	return true
}

func (cb *chainBuilder) buildExprAnd(value any) (expression, error) {
	exprs, err := cb.buildExprList(value)
	if err != nil {
		return nil, fmt.Errorf("building AND expression: %w", err)
	}
	return exprAnd(exprs), nil
}

type exprOr []expression

func (o exprOr) match(ctx requestCtx, request *dto.Request) bool {
	for _, rule := range o {
		if rule.match(ctx, request) {
			return true
		}
	}
	return false
}

func (cb *chainBuilder) buildExprOr(value any) (expression, error) {
	exprs, err := cb.buildExprList(value)
	if err != nil {
		return nil, fmt.Errorf("building OR expression: %w", err)
	}
	return exprOr(exprs), nil
}

type exprNot struct {
	rule expression
}

func (n *exprNot) match(ctx requestCtx, request *dto.Request) bool {
	return !n.rule.match(ctx, request)
}

func (cb *chainBuilder) buildExprNot(value any) (expression, error) {
	exprMap, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("NOT expression expects a map, got %T", value)
	}

	expr, err := cb.buildExpression(exprMap)
	if err != nil {
		return nil, fmt.Errorf("building NOT expression: %w", err)
	}

	return &exprNot{rule: expr}, nil
}

// Time expressions

type exprBefore struct {
	unixSec int64
}

func (bf *exprBefore) match(ctx requestCtx, request *dto.Request) bool {
	return request.Time < bf.unixSec
}

func buildExprBefore(value any) (expression, error) {
	timeStr, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("BEFORE expression expects a time string, got %T", value)
	}

	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, fmt.Errorf("parsing time for BEFORE expression: %w", err)
	}

	return &exprBefore{unixSec: t.Unix()}, nil
}

type exprAfter struct {
	unixSec int64
}

func (af *exprAfter) match(ctx requestCtx, request *dto.Request) bool {
	return request.Time > af.unixSec
}

func buildExprAfter(value any) (expression, error) {
	timeStr, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AFTER expression expects a time string, got %T", value)
	}

	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, fmt.Errorf("parsing time for AFTER expression: %w", err)
	}

	return &exprAfter{unixSec: t.Unix()}, nil
}

// IP address expressions

type exprClientIPCIDR struct {
	set netipx.IPSet
}

func (s *exprClientIPCIDR) match(ctx requestCtx, request *dto.Request) bool {
	return s.set.Contains(request.Client)
}

func buildExprClientIPCIDR(value any) (expression, error) {
	ipSet, err := buildExprIPSet(value)
	if err != nil {
		return nil, fmt.Errorf("building CLIENT-IP-CIDR expression: %w", err)
	}
	return &exprClientIPCIDR{set: *ipSet}, nil
}

type exprServerIPSet struct {
	set netipx.IPSet
}

func (s *exprServerIPSet) match(ctx requestCtx, request *dto.Request) bool {
	return s.set.Contains(request.Server)
}

func buildExprServerIPSet(value any) (expression, error) {
	ipSet, err := buildExprIPSet(value)
	if err != nil {
		return nil, fmt.Errorf("building SERVER-IP-CIDR expression: %w", err)
	}
	return &exprServerIPSet{set: *ipSet}, nil
}

// Method expressions

type exprMethod string

func (m exprMethod) match(ctx requestCtx, request *dto.Request) bool {
	return m == exprMethod(request.Method)
}

func buildExprMethod(value any) (expression, error) {
	method, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("METHOD expression expects a string, got %T", value)
	}
	return exprMethod(method), nil
}

// URL expressions

type exprURL string

func (u exprURL) match(ctx requestCtx, request *dto.Request) bool {
	return u == exprURL(request.URL)
}

func buildExprURL(value any) (expression, error) {
	url, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL expression expects a string, got %T", value)
	}
	return exprURL(url), nil
}

type exprURLSet map[string]struct{}

func (us exprURLSet) match(ctx requestCtx, request *dto.Request) bool {
	_, ok := us[request.URL]
	return ok
}

func buildExprURLSet(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("URL-SET: expected an array, got %T", value)
	}

	m := make(map[string]struct{}, len(rawSlice))
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("URL-SET: element at index %d is not a string: %T", i, v)
		}
		m[str] = struct{}{}
	}
	return exprURLSet(m), nil
}

type exprURLPrefix string

func (up exprURLPrefix) match(ctx requestCtx, request *dto.Request) bool {
	return strings.HasPrefix(request.URL, string(up))
}

func buildExprURLPrefix(value any) (expression, error) {
	prefix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-PREFIX expression expects a string, got %T", value)
	}
	return exprURLPrefix(prefix), nil
}

type exprURLSuffix string

func (up exprURLSuffix) match(ctx requestCtx, request *dto.Request) bool {
	return strings.HasSuffix(request.URL, string(up))
}

func buildExprURLSuffix(value any) (expression, error) {
	suffix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-SUFFIX expression expects a string, got %T", value)
	}
	return exprURLSuffix(suffix), nil
}

type exprURLKeyword string

func (uk exprURLKeyword) match(ctx requestCtx, request *dto.Request) bool {
	return strings.Contains(request.URL, string(uk))
}

func buildExprURLKeyword(value any) (expression, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-KEYWORD expression expects a string, got %T", value)
	}
	return exprURLKeyword(keyword), nil
}

type exprURLPrefixSet struct {
	trie trie.PrefixTrie[struct{}]
}

func (ups exprURLPrefixSet) match(ctx requestCtx, request *dto.Request) bool {
	_, ok := ups.trie.LongestPrefixMatch(request.URL)
	return ok
}

func buildExprURLPrefixSet(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("URL-PREFIX-SET: expected an array, got %T", value)
	}

	tb := trie.NewPrefixTrieBuilder[struct{}]()
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("URL-PREFIX-SET: element at index %d is not a string: %T", i, v)
		}
		tb.Add(str, struct{}{})
	}

	return exprURLPrefixSet{
		trie: tb.Build(),
	}, nil
}

type exprURLSuffixSet struct {
	trie trie.SuffixTrie[struct{}]
}

func (ups exprURLSuffixSet) match(ctx requestCtx, request *dto.Request) bool {
	_, ok := ups.trie.LongestSuffixMatch(request.URL)
	return ok
}

func buildExprURLSuffixSet(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("URL-SUFFIX-SET: expected an array, got %T", value)
	}

	tb := trie.NewSuffixTrieBuilder[struct{}]()
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("URL-SUFFIX-SET: element at index %d is not a string: %T", i, v)
		}
		tb.Add(str, struct{}{})
	}

	return exprURLSuffixSet{
		trie: tb.Build(),
	}, nil
}

type exprURLMap map[string]expression

func (us exprURLMap) match(ctx requestCtx, request *dto.Request) bool {
	expr, ok := us[request.URL]
	if !ok {
		return false
	}
	return expr.match(ctx, request)
}

func (cb *chainBuilder) buildExprURLMap(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("URL-MAP: expected an array, got %T", value)
	}

	mm := make(map[string]expression, len(rawSlice))
	var fallthroughGroup []string
CaseLoop:
	for i, v := range rawSlice {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("URL-MAP: element at index %d is not a map[string]any: %T", i, v)
		}
		if len(m) != 1 {
			return nil, fmt.Errorf("URL-MAP: expected exactly one key in map entry, got %d", len(m))
		}

		for k, v := range m {
			fallthroughGroup = append(fallthroughGroup, k)
			if v == nil {
				continue CaseLoop
			}

			expr, err := cb.buildExpression(v)
			if err != nil {
				return nil, err
			}

			for _, str := range fallthroughGroup {
				mm[str] = expr
			}
		}
		fallthroughGroup = fallthroughGroup[:0]
	}

	if len(fallthroughGroup) != 0 {
		return nil, fmt.Errorf("URL-MAP: ending case should not fallthrough")
	}

	return exprURLMap(mm), nil
}

type exprURLPrefixMap struct {
	trie trie.PrefixTrie[expression]
}

func (upm exprURLPrefixMap) match(ctx requestCtx, request *dto.Request) bool {
	expr, ok := upm.trie.LongestPrefixMatch(request.URL)
	if !ok {
		return false
	}
	return expr.match(ctx, request)
}

func (cb *chainBuilder) buildExprURLPrefixMap(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("URL-PREFIX-MAP: expected an array, got %T", value)
	}

	tb := trie.NewPrefixTrieBuilder[expression]()
	var fallthroughGroup []string
CaseLoop:
	for i, v := range rawSlice {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("URL-PREFIX-MAP: element at index %d is not a map[string]any: %T", i, v)
		}
		if len(m) != 1 {
			return nil, fmt.Errorf("URL-PREFIX-MAP: expected exactly one key in map entry, got %d", len(m))
		}

		for k, v := range m {
			fallthroughGroup = append(fallthroughGroup, k)
			if v == nil {
				continue CaseLoop
			}

			expr, err := cb.buildExpression(v)
			if err != nil {
				return nil, err
			}

			for _, str := range fallthroughGroup {
				tb.Add(str, expr)
			}
		}
		fallthroughGroup = fallthroughGroup[:0]
	}

	if len(fallthroughGroup) != 0 {
		return nil, fmt.Errorf("URL-PREFIX-MAP: ending case should not fallthrough")
	}

	return exprURLPrefixMap{
		trie: tb.Build(),
	}, nil
}

type exprURLSuffixMap struct {
	trie trie.SuffixTrie[expression]
}

func (upm exprURLSuffixMap) match(ctx requestCtx, request *dto.Request) bool {
	expr, ok := upm.trie.LongestSuffixMatch(request.URL)
	if !ok {
		return false
	}
	return expr.match(ctx, request)
}

func (cb *chainBuilder) buildExprURLSuffixMap(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("URL-SUFFIX-MAP: expected an array, got %T", value)
	}

	tb := trie.NewSuffixTrieBuilder[expression]()
	var fallthroughGroup []string
CaseLoop:
	for i, v := range rawSlice {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("URL-SUFFIX-MAP: element at index %d is not a map[string]any: %T", i, v)
		}
		if len(m) != 1 {
			return nil, fmt.Errorf("URL-SUFFIX-MAP: expected exactly one key in map entry, got %d", len(m))
		}

		for k, v := range m {
			fallthroughGroup = append(fallthroughGroup, k)
			if v == nil {
				continue CaseLoop
			}
			expr, err := cb.buildExpression(v)
			if err != nil {
				return nil, err
			}
			for _, str := range fallthroughGroup {
				tb.Add(str, expr)
			}
		}
		fallthroughGroup = fallthroughGroup[:0]
	}

	if len(fallthroughGroup) != 0 {
		return nil, fmt.Errorf("URL-SUFFIX-MAP: ending case should not fallthrough")
	}

	return exprURLSuffixMap{
		trie: tb.Build(),
	}, nil
}

// Status expressions

type exprStatus int

func (s exprStatus) match(ctx requestCtx, request *dto.Request) bool {
	return s == exprStatus(request.Status)
}

func buildExprStatus(value any) (expression, error) {
	switch v := value.(type) {
	case int:
		return exprStatus(v), nil
	case int64:
		return exprStatus(int(v)), nil
	case uint64:
		return exprStatus(int(v)), nil
	case float64:
		return exprStatus(int(v)), nil
	case string:
		status, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("STATUS expression expects an integer, got %q", v)
		}
		return exprStatus(status), nil
	default:
		return nil, fmt.Errorf("STATUS expression expects an integer, got %T", value)
	}
}

type exprStatusClass int

const (
	Informational exprStatusClass = 1
	Successful    exprStatusClass = 2
	Redirection   exprStatusClass = 3
	ClientError   exprStatusClass = 4
	ServerError   exprStatusClass = 5
)

func (sc exprStatusClass) match(ctx requestCtx, request *dto.Request) bool {
	return sc == exprStatusClass(request.Status/100)
}

func buildExprStatusClass(value any) (expression, error) {
	switch v := value.(type) {
	case int:
		return exprStatusClass(v), nil
	case int64:
		return exprStatusClass(int(v)), nil
	case uint64:
		return exprStatusClass(int(v)), nil
	case float64:
		return exprStatusClass(int(v)), nil
	case string:
		// Try to parse as integer first
		if class, err := strconv.Atoi(v); err == nil {
			return exprStatusClass(class), nil
		}

		// Try to parse as named status class
		switch strings.ToLower(v) {
		case "informational", "1xx":
			return exprStatusClass(Informational), nil
		case "successful", "2xx":
			return exprStatusClass(Successful), nil
		case "redirection", "3xx":
			return exprStatusClass(Redirection), nil
		case "client_error", "clienterror", "4xx":
			return exprStatusClass(ClientError), nil
		case "server_error", "servererror", "5xx":
			return exprStatusClass(ServerError), nil
		default:
			return nil, fmt.Errorf("STATUS-CLASS expression: unknown status class %q", v)
		}
	default:
		return nil, fmt.Errorf("STATUS-CLASS expression expects an integer or string, got %T", value)
	}
}

// Sent expressions

type exprSentMoreThan int64

func (smt exprSentMoreThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Sent > int64(smt)
}

func buildExprSentMoreThan(value any) (expression, error) {
	sent, err := parseExprByteSize(value)
	if err != nil {
		return nil, fmt.Errorf("building SENT-MORE-THAN expression: %w", err)
	}
	return exprSentMoreThan(sent), nil
}

type exprSentLessThan int64

func (slt exprSentLessThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Sent < int64(slt)
}

func buildExprSentLessThan(value any) (expression, error) {
	sent, err := parseExprByteSize(value)
	if err != nil {
		return nil, fmt.Errorf("building SENT-LESS-THAN expression: %w", err)
	}
	return exprSentLessThan(sent), nil
}

// Duration expressions

type exprTookLongerThan time.Duration

func (tlt exprTookLongerThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Duration > time.Duration(tlt)
}

func buildExprTookLongerThan(value any) (expression, error) {
	duration, err := parseExprDuration(value)
	if err != nil {
		return nil, fmt.Errorf("building TOOK-LONGER-THAN expression: %w", err)
	}
	return exprTookLongerThan(duration), nil
}

type exprTookShorterThan time.Duration

func (tst exprTookShorterThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Duration < time.Duration(tst)
}

func buildExprTookShorterThan(value any) (expression, error) {
	duration, err := parseExprDuration(value)
	if err != nil {
		return nil, fmt.Errorf("building TOOK-SHORTER-THAN expression: %w", err)
	}
	return exprTookShorterThan(duration), nil
}

// Host expressions

type exprHost string

func (h exprHost) match(ctx requestCtx, request *dto.Request) bool {
	return h == exprHost(request.Host)
}

func buildExprHost(value any) (expression, error) {
	host, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST expression expects a string, got %T", value)
	}
	return exprHost(host), nil
}

type exprHostSuffix string

func (hs exprHostSuffix) match(ctx requestCtx, request *dto.Request) bool {
	return strings.HasSuffix(request.Host, string(hs))
}

func buildExprHostSuffix(value any) (expression, error) {
	suffix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST-SUFFIX expression expects a string, got %T", value)
	}
	return exprHostSuffix(suffix), nil
}

type exprHostKeyword string

func (hk exprHostKeyword) match(ctx requestCtx, request *dto.Request) bool {
	return strings.Contains(request.Host, string(hk))
}

func buildExprHostKeyword(value any) (expression, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST-KEYWORD expression expects a string, got %T", value)
	}
	return exprHostKeyword(keyword), nil
}

// Agent expressions

type exprAgent string

func (a exprAgent) match(ctx requestCtx, request *dto.Request) bool {
	return a == exprAgent(request.Agent)
}

func buildExprAgent(value any) (expression, error) {
	agent, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AGENT expression expects a string, got %T", value)
	}
	return exprAgent(agent), nil
}

type exprAgentKeyword string

func (ak exprAgentKeyword) match(ctx requestCtx, request *dto.Request) bool {
	return strings.Contains(request.Agent, string(ak))
}

func buildExprAgentKeyword(value any) (expression, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AGENT-KEYWORD expression expects a string, got %T", value)
	}
	return exprAgentKeyword(keyword), nil
}

type exprAgentSet map[string]struct{}

func (as exprAgentSet) match(ctx requestCtx, request *dto.Request) bool {
	_, ok := as[request.Agent]
	return ok
}

func buildExprAgentSet(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected an array, got %T", value)
	}

	m := make(map[string]struct{}, len(rawSlice))
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element at index %d is not a string: %T", i, v)
		}
		m[str] = struct{}{}
	}
	return exprAgentSet(m), nil
}

// Helper functions

func buildExprIPSet(value any) (*netipx.IPSet, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("IP set expression expects a list, got %T", value)
	}

	builder := &netipx.IPSetBuilder{}
	for i, item := range items {
		itemStr, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("IP set item %d: expected string, got %T", i, item)
		}

		if prefix, err := netip.ParsePrefix(itemStr); err == nil {
			builder.AddPrefix(prefix)
			continue
		}

		return nil, fmt.Errorf("IP set item %d: invalid CIDR: %s", i, itemStr)
	}

	ipSet, err := builder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("building IP set: %w", err)
	}

	return ipSet, nil
}

func (cb *chainBuilder) buildExprList(value any) ([]expression, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list of expressions, got %T", value)
	}

	exprs := make([]expression, 0, len(items))
	for i, item := range items {
		expr, err := cb.buildExpression(item)
		if err != nil {
			return nil, fmt.Errorf("expression %d: %w", i, err)
		}

		exprs = append(exprs, expr)
	}

	return exprs, nil
}

func parseExprByteSize(value any) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case uint64:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		return units.FromHumanSize(v)
	default:
		return 0, fmt.Errorf("expected byte size, got %v", value)
	}
}

func parseExprFloatByteSize(value any) (float64, error) {
	switch v := value.(type) {
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	case float64:
		return v, nil
	case string:
		s, err := units.FromHumanSize(v)
		if err != nil {
			return 0, err
		}
		return float64(s), nil
	default:
		return 0, fmt.Errorf("expected byte size, got %v", value)
	}
}

func parseExprDuration(value any) (time.Duration, error) {
	switch v := value.(type) {
	case string:
		return time.ParseDuration(v)
	case int:
		return time.Duration(v) * time.Second, nil
	case int64:
		return time.Duration(v) * time.Second, nil
	case uint64:
		return time.Duration(v) * time.Second, nil
	case float64:
		return time.Duration(v) * time.Second, nil
	default:
		return 0, fmt.Errorf("expected duration string or number of seconds, got %T", value)
	}
}
