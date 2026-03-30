package filter

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-units"
	"go4.org/netipx"
)

// Build creates a FilterRule from a configuration value.
func Build(config any) (FilterRule, error) {
	switch v := config.(type) {
	case string:
		return buildFromString(v)
	case map[string]any:
		return buildFromMap(v)
	default:
		return nil, fmt.Errorf("expected string or map, got %T", config)
	}
}

func buildFromString(s string) (FilterRule, error) {
	switch strings.ToUpper(s) {
	case "ALL":
		return All{}, nil
	case "NONE":
		return None{}, nil
	default:
		return nil, fmt.Errorf("unknown rule string: %s", s)
	}
}

func buildFromMap(m map[string]any) (FilterRule, error) {
	if len(m) != 1 {
		return nil, fmt.Errorf("expected exactly one key in rule map, got %d", len(m))
	}

	for key, value := range m {
		upperKey := strings.ToUpper(key)
		switch upperKey {
		// Conditional rules
		case "ALL":
			return All{}, nil
		case "NONE":
			return None{}, nil
		case "AND":
			return buildAnd(value)
		case "OR":
			return buildOr(value)
		case "NOT":
			return buildNot(value)

		// Time rules
		case "BEFORE":
			return buildBefore(value)
		case "AFTER":
			return buildAfter(value)

		// IP address rules
		case "CLIENT-IP-CIDR":
			return buildClientIPSet(value)
		case "SERVER-IP-CIDR":
			return buildServerIPSet(value)

		// Method rules
		case "METHOD":
			return buildMethod(value)

		// URL rules
		case "URL":
			return buildURL(value)
		case "URL-PREFIX":
			return buildURLPrefix(value)
		case "URL-KEYWORD":
			return buildURLKeyword(value)

		// Status rules
		case "STATUS":
			return buildStatus(value)
		case "STATUS-CLASS":
			return buildStatusClass(value)

		// Sent rules
		case "SENT-MORE-THAN":
			return buildSentMoreThan(value)
		case "SENT-LESS-THAN":
			return buildSentLessThan(value)

		// Duration rules
		case "TOOK-LONGER-THAN":
			return buildTookLongerThan(value)
		case "TOOK-SHORTER-THAN":
			return buildTookShorterThan(value)

		// Host rules
		case "HOST":
			return buildHost(value)
		case "HOST-SUFFIX":
			return buildHostSuffix(value)
		case "HOST-KEYWORD":
			return buildHostKeyword(value)

		// Agent rules
		case "AGENT":
			return buildAgent(value)
		case "AGENT-KEYWORD":
			return buildAgentKeyword(value)

		default:
			return nil, fmt.Errorf("unknown rule type: %s", key)
		}
	}

	// This should never be reached
	return nil, fmt.Errorf("invalid rule map")
}

// Helper functions for building specific rule types

func buildAnd(value any) (FilterRule, error) {
	rules, err := buildRuleList(value)
	if err != nil {
		return nil, fmt.Errorf("building AND rule: %w", err)
	}
	return And(rules), nil
}

func buildOr(value any) (FilterRule, error) {
	rules, err := buildRuleList(value)
	if err != nil {
		return nil, fmt.Errorf("building OR rule: %w", err)
	}
	return Or(rules), nil
}

func buildNot(value any) (FilterRule, error) {
	ruleMap, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("NOT rule expects a map, got %T", value)
	}

	rule, err := Build(ruleMap)
	if err != nil {
		return nil, fmt.Errorf("building NOT rule: %w", err)
	}

	return &Not{Rule: rule}, nil
}

func buildBefore(value any) (FilterRule, error) {
	timeStr, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("BEFORE rule expects a time string, got %T", value)
	}

	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, fmt.Errorf("parsing time for BEFORE rule: %w", err)
	}

	return &Before{Time: t}, nil
}

func buildAfter(value any) (FilterRule, error) {
	timeStr, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AFTER rule expects a time string, got %T", value)
	}

	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return nil, fmt.Errorf("parsing time for AFTER rule: %w", err)
	}

	return &After{Time: t}, nil
}

func buildClientIPSet(value any) (FilterRule, error) {
	ipSet, err := buildIPSet(value)
	if err != nil {
		return nil, fmt.Errorf("building CLIENT-IP-CIDR rule: %w", err)
	}
	return &ClientIPSet{Set: *ipSet}, nil
}

func buildServerIPSet(value any) (FilterRule, error) {
	ipSet, err := buildIPSet(value)
	if err != nil {
		return nil, fmt.Errorf("building SERVER-IP-CIDR rule: %w", err)
	}
	return &ServerIPSet{Set: *ipSet}, nil
}

func buildIPSet(value any) (*netipx.IPSet, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("IP set rule expects a list, got %T", value)
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

func buildMethod(value any) (FilterRule, error) {
	method, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("METHOD rule expects a string, got %T", value)
	}
	return Method(method), nil
}

func buildURL(value any) (FilterRule, error) {
	url, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL rule expects a string, got %T", value)
	}
	return URL(url), nil
}

func buildURLPrefix(value any) (FilterRule, error) {
	prefix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-PREFIX rule expects a string, got %T", value)
	}
	return URLPrefix(prefix), nil
}

func buildURLKeyword(value any) (FilterRule, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("URL-KEYWORD rule expects a string, got %T", value)
	}
	return URLKeyword(keyword), nil
}

func buildStatus(value any) (FilterRule, error) {
	switch v := value.(type) {
	case int:
		return Status(v), nil
	case float64:
		return Status(int(v)), nil
	case string:
		status, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("STATUS rule expects an integer, got %q", v)
		}
		return Status(status), nil
	default:
		return nil, fmt.Errorf("STATUS rule expects an integer, got %T", value)
	}
}

func buildStatusClass(value any) (FilterRule, error) {
	switch v := value.(type) {
	case int:
		return StatusClass(v), nil
	case float64:
		return StatusClass(int(v)), nil
	case string:
		// Try to parse as integer first
		if class, err := strconv.Atoi(v); err == nil {
			return StatusClass(class), nil
		}

		// Try to parse as named status class
		switch strings.ToLower(v) {
		case "informational", "1xx":
			return StatusClass(Informational), nil
		case "successful", "2xx":
			return StatusClass(Successful), nil
		case "redirection", "3xx":
			return StatusClass(Redirection), nil
		case "client_error", "clienterror", "4xx":
			return StatusClass(ClientError), nil
		case "server_error", "servererror", "5xx":
			return StatusClass(ServerError), nil
		default:
			return nil, fmt.Errorf("STATUS-CLASS rule: unknown status class %q", v)
		}
	default:
		return nil, fmt.Errorf("STATUS-CLASS rule expects an integer or string, got %T", value)
	}
}

func buildSentMoreThan(value any) (FilterRule, error) {
	sent, err := parseByteSize(value)
	if err != nil {
		return nil, fmt.Errorf("building SENT-MORE-THAN rule: %w", err)
	}
	return SentMoreThan(sent), nil
}

func buildSentLessThan(value any) (FilterRule, error) {
	sent, err := parseByteSize(value)
	if err != nil {
		return nil, fmt.Errorf("building SENT-LESS-THAN rule: %w", err)
	}
	return SentLessThan(sent), nil
}

func buildTookLongerThan(value any) (FilterRule, error) {
	duration, err := parseDuration(value)
	if err != nil {
		return nil, fmt.Errorf("building TOOK-LONGER-THAN rule: %w", err)
	}
	return TookLongerThan(duration), nil
}

func buildTookShorterThan(value any) (FilterRule, error) {
	duration, err := parseDuration(value)
	if err != nil {
		return nil, fmt.Errorf("building TOOK-SHORTER-THAN rule: %w", err)
	}
	return TookShorterThan(duration), nil
}

func buildHost(value any) (FilterRule, error) {
	host, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST rule expects a string, got %T", value)
	}
	return Host(host), nil
}

func buildHostSuffix(value any) (FilterRule, error) {
	suffix, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST-SUFFIX rule expects a string, got %T", value)
	}
	return HostSuffix(suffix), nil
}

func buildHostKeyword(value any) (FilterRule, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("HOST-KEYWORD rule expects a string, got %T", value)
	}
	return HostKeyword(keyword), nil
}

func buildAgent(value any) (FilterRule, error) {
	agent, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AGENT rule expects a string, got %T", value)
	}
	return Agent(agent), nil
}

func buildAgentKeyword(value any) (FilterRule, error) {
	keyword, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("AGENT-KEYWORD rule expects a string, got %T", value)
	}
	return AgentKeyword(keyword), nil
}

// Helper functions

func buildRuleList(value any) ([]FilterRule, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list of rules, got %T", value)
	}

	rules := make([]FilterRule, 0, len(items))
	for i, item := range items {
		rule, err := Build(item)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func parseByteSize(value any) (int64, error) {
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

func parseDuration(value any) (time.Duration, error) {
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
