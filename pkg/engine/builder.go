package engine

import (
	"errors"
	"fmt"
	"strings"
)

type ChainConfig struct {
	Name  string       `mapstructure:"name"`
	Rules []RuleConfig `mapstructure:"rules"`
}

type RuleConfig struct {
	Statement   any   `mapstructure:"statement"`
	Expressions []any `mapstructure:"expressions"`
}

type chainBuilder struct {
	re        *RuleEngine
	bucketMap map[string]exprBucket
}

func (cb *chainBuilder) buildChains(ch []ChainConfig) (main chain, err error) {
	if len(ch) == 0 {
		return chain{}, errors.New("no chains provided")
	}

	chainMap := make(map[string]chain)

	for _, cc := range ch {
		c, err := cb.buildChain(chainMap, cc)
		if err != nil {
			return chain{}, err
		}
		chainMap[c.name] = c
	}

	main, ok := chainMap["main"]
	if !ok {
		return chain{}, errors.New("no main chain")
	}
	return main, nil
}

func (cb *chainBuilder) buildChain(chainMap map[string]chain, ch ChainConfig) (chain, error) {
	_, ok := chainMap[ch.Name]
	if ok {
		return chain{}, fmt.Errorf("duplicate chain name: %s", ch.Name)
	}

	rules := make([]rule, 0, len(ch.Rules))

	for _, r := range ch.Rules {
		ru, err := cb.buildRule(chainMap, r)
		if err != nil {
			return chain{}, err
		}
		rules = append(rules, ru)
	}

	return chain{
		name:  ch.Name,
		rules: rules,
	}, nil
}

func (cb *chainBuilder) buildRule(chainMap map[string]chain, r RuleConfig) (rule, error) {
	exprs, err := cb.buildExprList(r.Expressions)
	if err != nil {
		return rule{}, err
	}

	stmt, err := cb.buildStatement(chainMap, r.Statement)
	if err != nil {
		return rule{}, err
	}

	return rule{
		expressions: exprs,
		statement:   stmt,
	}, nil
}

func (cb *chainBuilder) buildExpression(expr any) (expression, error) {
	switch v := expr.(type) {
	case string:
		switch strings.ToUpper(v) {
		case "ALL":
			return exprAll{}, nil
		case "NONE":
			return exprNone{}, nil
		default:
			return nil, fmt.Errorf("unknown expression string: %s", v)
		}
	default:
		return nil, fmt.Errorf("buildExpression: expected string or map, got %T", expr)
	case map[string]any:
		if len(v) != 1 {
			return nil, fmt.Errorf("expected exactly one key in expression map, got %d", len(v))
		}

		for key, value := range v {
			upperKey := strings.ToUpper(key)
			switch upperKey {
			// Conditional expressions
			case "ALL":
				return exprAll{}, nil
			case "NONE":
				return exprNone{}, nil
			case "AND":
				return cb.buildExprAnd(value)
			case "OR":
				return cb.buildExprOr(value)
			case "NOT":
				return cb.buildExprNot(value)

			// Time expressions
			case "BEFORE":
				return buildExprBefore(value)
			case "AFTER":
				return buildExprAfter(value)

			// IP address expressions
			case "CLIENT-IP-CIDR":
				return buildExprClientIPCIDR(value)
			case "SERVER-IP-CIDR":
				return buildExprServerIPSet(value)

			// Method expressions
			case "METHOD":
				return buildExprMethod(value)

			// URL expressions
			case "URL":
				return buildExprURL(value)
			case "URL-PREFIX":
				return buildExprURLPrefix(value)
			case "URL-SUFFIX":
				return buildExprURLSuffix(value)
			case "URL-KEYWORD":
				return buildExprURLKeyword(value)
			case "URL-SET":
				return buildExprURLSet(value)
			case "URL-PREFIX-SET":
				return buildExprURLPrefixSet(value)
			case "URL-SUFFIX-SET":
				return buildExprURLSuffixSet(value)
			case "URL-MAP":
				return cb.buildExprURLMap(value)
			case "URL-PREFIX-MAP":
				return cb.buildExprURLPrefixMap(value)
			case "URL-SUFFIX-MAP":
				return cb.buildExprURLSuffixMap(value)

			// Status expressions
			case "STATUS":
				return buildExprStatus(value)
			case "STATUS-CLASS":
				return buildExprStatusClass(value)

			// Sent expressions
			case "SENT-MORE-THAN":
				return buildExprSentMoreThan(value)
			case "SENT-LESS-THAN":
				return buildExprSentLessThan(value)

			// Duration expressions
			case "TOOK-LONGER-THAN":
				return buildExprTookLongerThan(value)
			case "TOOK-SHORTER-THAN":
				return buildExprTookShorterThan(value)

			// Host expressions
			case "HOST":
				return buildExprHost(value)
			case "HOST-SUFFIX":
				return buildExprHostSuffix(value)
			case "HOST-KEYWORD":
				return buildExprHostKeyword(value)

			// Agent expressions
			case "AGENT":
				return buildExprAgent(value)
			case "AGENT-KEYWORD":
				return buildExprAgentKeyword(value)
			case "AGENT-SET":
				return buildExprAgentSet(value)

			// Bucket expressions
			case "BYTE-BUCKET":
				bkt, err := cb.buildExprByteBucket(value)
				if err != nil {
					return nil, err
				}
				cb.bucketMap[bkt.name()] = bkt
				return bkt, nil
			case "FREQ-BUCKET":
				bkt, err := cb.buildExprFreqBucket(value)
				if err != nil {
					return nil, err
				}
				cb.bucketMap[bkt.name()] = bkt
				return bkt, nil
			case "FILE-RATIO-BUCKET":
				bkt, err := cb.buildExprFileRatioBucket(value)
				if err != nil {
					return nil, err
				}
				cb.bucketMap[bkt.name()] = bkt
				return bkt, nil

			default:
				return nil, fmt.Errorf("unknown expression type: %s", key)
			}
		}
	}

	// This should never be reached
	return nil, fmt.Errorf("faulty buildExpression; check implementation")
}

func (cb *chainBuilder) buildStatement(chainMap map[string]chain, stmt any) (statement, error) {
	switch v := stmt.(type) {
	case string:
		switch strings.ToUpper(v) {
		case "STOP":
			return &stmtStop{}, nil
		case "CONTINUE":
			return &stmtContinue{}, nil
		default:
			return nil, fmt.Errorf("unknown statement string: %s", v)
		}
	default:
		return nil, fmt.Errorf("buildStatement: expected string or map, got %T", stmt)
	case map[string]any:
		if len(v) != 1 {
			return nil, fmt.Errorf("expected exactly one key in statement map, got %d", len(v))
		}

		for key, value := range v {
			upperKey := strings.ToUpper(key)
			switch upperKey {
			case "STOP":
				return &stmtStop{}, nil
			case "CONTINUE":
				return &stmtContinue{}, nil
			case "GOTO":
				return buildStmtGoto(chainMap, value)
			case "JUMP":
				return buildStmtJump(chainMap, value)
			case "LOG":
				return buildStmtLog(value)
			case "BAN":
				return cb.buildStmtBan(value)
			default:
				return nil, fmt.Errorf("unknown statement type: %s", key)
			}
		}

		// This should never be reached
		return nil, fmt.Errorf("faulty buildStatement; check implementation")
	}
}
