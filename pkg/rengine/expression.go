package rengine

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/trie"
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

type exprOr []expression

func (o exprOr) match(ctx requestCtx, request *dto.Request) bool {
	for _, rule := range o {
		if rule.match(ctx, request) {
			return true
		}
	}
	return false
}

type exprNot struct {
	Rule expression
}

func (n *exprNot) match(ctx requestCtx, request *dto.Request) bool {
	return !n.Rule.match(ctx, request)
}

// Time expressions

type exprBefore struct {
	Time time.Time
}

func (bf *exprBefore) match(ctx requestCtx, request *dto.Request) bool {
	return request.Time.Before(bf.Time)
}

type exprAfter struct {
	Time time.Time
}

func (af *exprAfter) match(ctx requestCtx, request *dto.Request) bool {
	return request.Time.After(af.Time)
}

// IP address expressions

type exprClientIPCIDR struct {
	Set netipx.IPSet
}

func (s *exprClientIPCIDR) match(ctx requestCtx, request *dto.Request) bool {
	return s.Set.Contains(request.Client)
}

type exprServerIPSet struct {
	Set netipx.IPSet
}

func (s *exprServerIPSet) match(ctx requestCtx, request *dto.Request) bool {
	return s.Set.Contains(request.Server)
}

// Method expressions

type exprMethod string

func (m exprMethod) match(ctx requestCtx, request *dto.Request) bool {
	return m == exprMethod(request.Method)
}

// URL expressions

type exprURL string

func (u exprURL) match(ctx requestCtx, request *dto.Request) bool {
	return u == exprURL(request.URL)
}

type exprURLSet map[string]struct{}

func (us exprURLSet) match(ctx requestCtx, request *dto.Request) bool {
	_, ok := us[request.URL]
	return ok
}

type exprURLPrefix string

func (up exprURLPrefix) match(ctx requestCtx, request *dto.Request) bool {
	return strings.HasPrefix(request.URL, string(up))
}

type exprURLSuffix string

func (up exprURLSuffix) match(ctx requestCtx, request *dto.Request) bool {
	return strings.HasSuffix(request.URL, string(up))
}

type exprURLKeyword string

func (uk exprURLKeyword) match(ctx requestCtx, request *dto.Request) bool {
	return strings.Contains(request.URL, string(uk))
}

type exprURLPrefixSet struct {
	trie trie.Trie
}

func (ups exprURLPrefixSet) match(ctx requestCtx, request *dto.Request) bool {
	return ups.trie.HasPrefixOf(request.URL)
}

// Status expressions

type exprStatus int

func (s exprStatus) match(ctx requestCtx, request *dto.Request) bool {
	return s == exprStatus(request.Status)
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

// Sent expressions

type exprSentMoreThan int64

func (smt exprSentMoreThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Sent > int64(smt)
}

type exprSentLessThan int64

func (slt exprSentLessThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Sent < int64(slt)
}

// Duration expressions

type exprTookLongerThan time.Duration

func (tlt exprTookLongerThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Duration > time.Duration(tlt)
}

type exprTookShorterThan time.Duration

func (tst exprTookShorterThan) match(ctx requestCtx, request *dto.Request) bool {
	return request.Duration < time.Duration(tst)
}

// Host expressions

type exprHost string

func (h exprHost) match(ctx requestCtx, request *dto.Request) bool {
	return h == exprHost(request.Host)
}

type exprHostSuffix string

func (hs exprHostSuffix) match(ctx requestCtx, request *dto.Request) bool {
	return strings.HasSuffix(request.Host, string(hs))
}

type exprHostKeyword string

func (hk exprHostKeyword) match(ctx requestCtx, request *dto.Request) bool {
	return strings.Contains(request.Host, string(hk))
}

// Agent expressions

type exprAgent string

func (a exprAgent) match(ctx requestCtx, request *dto.Request) bool {
	return a == exprAgent(request.Agent)
}

type exprAgentKeyword string

func (ak exprAgentKeyword) match(ctx requestCtx, request *dto.Request) bool {
	return strings.Contains(request.Agent, string(ak))
}

type exprAgentSet map[string]struct{}

func (as exprAgentSet) match(ctx requestCtx, request *dto.Request) bool {
	_, ok := as[request.Agent]
	return ok
}

// Builder methods for expressions

func (re *RuleEngine) buildExprAnd(value any) (expression, error) {
	exprs, err := re.buildExprList(value)
	if err != nil {
		return nil, fmt.Errorf("building AND expression: %w", err)
	}
	return exprAnd(exprs), nil
}

func (re *RuleEngine) buildExprOr(value any) (expression, error) {
	exprs, err := re.buildExprList(value)
	if err != nil {
		return nil, fmt.Errorf("building OR expression: %w", err)
	}
	return exprOr(exprs), nil
}

func (re *RuleEngine) buildExprNot(value any) (expression, error) {
	exprMap, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("NOT expression expects a map, got %T", value)
	}

	expr, err := re.buildExpression(exprMap)
	if err != nil {
		return nil, fmt.Errorf("building NOT expression: %w", err)
	}

	return &exprNot{Rule: expr}, nil
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

	return &exprBefore{Time: t}, nil
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

	return &exprAfter{Time: t}, nil
}

func buildExprClientIPCIDR(value any) (expression, error) {
	ipSet, err := buildExprIPSet(value)
	if err != nil {
		return nil, fmt.Errorf("building CLIENT-IP-CIDR expression: %w", err)
	}
	return &exprClientIPCIDR{Set: *ipSet}, nil
}

func buildExprServerIPSet(value any) (expression, error) {
	ipSet, err := buildExprIPSet(value)
	if err != nil {
		return nil, fmt.Errorf("building SERVER-IP-CIDR expression: %w", err)
	}
	return &exprServerIPSet{Set: *ipSet}, nil
}

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

		return nil, fmt.Errorf("IP set item %d: invalid IP or CIDR: %s", i, itemStr)
	}

	ipSet, err := builder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("building IP set: %w", err)
	}

	return ipSet, nil
}

func buildExprMethod(value any) (expression, error) {
	method, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("METHOD expression expects a string, got %T", value)
	}
	return exprMethod(method), nil
}

func buildExprURL(value any) (expression, error) {
	url, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL expression expects a string, got %T", value)
	}
	return exprURL(url), nil
}

func buildExprURLPrefix(value any) (expression, error) {
	prefix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-PREFIX expression expects a string, got %T", value)
	}
	return exprURLPrefix(prefix), nil
}

func buildExprURLSuffix(value any) (expression, error) {
	suffix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-SUFFIX expression expects a string, got %T", value)
	}
	return exprURLSuffix(suffix), nil
}

func buildExprURLKeyword(value any) (expression, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-KEYWORD expression expects a string, got %T", value)
	}
	return exprURLKeyword(keyword), nil
}

func buildExprURLPrefixSet(value any) (expression, error) {
	rawSlice, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected an array, got %T", value)
	}

	prefixes := make([]string, len(rawSlice))
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element at index %d is not a string: %T", i, v)
		}
		prefixes[i] = str
	}

	return exprURLPrefixSet{
		trie: trie.New(prefixes),
	}, nil
}

func buildExprURLSet(value any) (expression, error) {
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
	return exprURLSet(m), nil
}

func buildExprStatus(value any) (expression, error) {
	switch v := value.(type) {
	case int:
		return exprStatus(v), nil
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

func buildExprStatusClass(value any) (expression, error) {
	switch v := value.(type) {
	case int:
		return exprStatusClass(v), nil
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

func buildExprSentMoreThan(value any) (expression, error) {
	sent, err := parseExprByteSize(value)
	if err != nil {
		return nil, fmt.Errorf("building SENT-MORE-THAN expression: %w", err)
	}
	return exprSentMoreThan(sent), nil
}

func buildExprSentLessThan(value any) (expression, error) {
	sent, err := parseExprByteSize(value)
	if err != nil {
		return nil, fmt.Errorf("building SENT-LESS-THAN expression: %w", err)
	}
	return exprSentLessThan(sent), nil
}

func buildExprTookLongerThan(value any) (expression, error) {
	duration, err := parseExprDuration(value)
	if err != nil {
		return nil, fmt.Errorf("building TOOK-LONGER-THAN expression: %w", err)
	}
	return exprTookLongerThan(duration), nil
}

func buildExprTookShorterThan(value any) (expression, error) {
	duration, err := parseExprDuration(value)
	if err != nil {
		return nil, fmt.Errorf("building TOOK-SHORTER-THAN expression: %w", err)
	}
	return exprTookShorterThan(duration), nil
}

func buildExprHost(value any) (expression, error) {
	host, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST expression expects a string, got %T", value)
	}
	return exprHost(host), nil
}

func buildExprHostSuffix(value any) (expression, error) {
	suffix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST-SUFFIX expression expects a string, got %T", value)
	}
	return exprHostSuffix(suffix), nil
}

func buildExprHostKeyword(value any) (expression, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST-KEYWORD expression expects a string, got %T", value)
	}
	return exprHostKeyword(keyword), nil
}

func buildExprAgent(value any) (expression, error) {
	agent, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AGENT expression expects a string, got %T", value)
	}
	return exprAgent(agent), nil
}

func buildExprAgentKeyword(value any) (expression, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AGENT-KEYWORD expression expects a string, got %T", value)
	}
	return exprAgentKeyword(keyword), nil
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

func (re *RuleEngine) buildExprList(value any) ([]expression, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list of expressions, got %T", value)
	}

	exprs := make([]expression, 0, len(items))
	for i, item := range items {
		expr, err := re.buildExpression(item)
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
	case float64:
		return int64(v), nil
	case string:
		return units.FromHumanSize(string(v))
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
	case float64:
		return time.Duration(v) * time.Second, nil
	default:
		return 0, fmt.Errorf("expected duration string or number of seconds, got %T", value)
	}
}
