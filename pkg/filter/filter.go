package filter

import (
	"strings"
	"time"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/trie"
	"go4.org/netipx"
)

type FilterRule interface {
	// Returns nil if match success;
	// Else return reason
	Match(r *dto.Request) bool
}

// Logical rules

type All struct{}

func (a All) Match(r *dto.Request) bool { return true }

type None struct{}

func (n None) Match(r *dto.Request) bool { return false }

type And []FilterRule

func (a And) Match(r *dto.Request) bool {
	for _, rule := range a {
		if !rule.Match(r) {
			return false
		}
	}
	return true
}

type Or []FilterRule

func (o Or) Match(r *dto.Request) bool {
	for _, rule := range o {
		if rule.Match(r) {
			return true
		}
	}
	return false
}

type Not struct {
	Rule FilterRule
}

func (n *Not) Match(r *dto.Request) bool {
	return !n.Rule.Match(r)
}

// Time rules

type Before struct {
	Time time.Time
}

func (bf *Before) Match(r *dto.Request) bool {
	return r.Time.Before(bf.Time)
}

type After struct {
	Time time.Time
}

func (af *After) Match(r *dto.Request) bool {
	return r.Time.After(af.Time)
}

// IP address rules

type ClientIPSet struct {
	Set netipx.IPSet
}

func (s *ClientIPSet) Match(r *dto.Request) bool {
	return s.Set.Contains(r.Client)
}

type ServerIPSet struct {
	Set netipx.IPSet
}

func (s *ServerIPSet) Match(r *dto.Request) bool {
	return s.Set.Contains(r.Server)
}

// Method rules

type Method string

func (m Method) Match(r *dto.Request) bool {
	return m == Method(r.Method)
}

// URL rules

type URL string

func (u URL) Match(r *dto.Request) bool {
	return u == URL(r.URL)
}

type URLSet map[string]struct{}

func (us URLSet) Match(r *dto.Request) bool {
	_, ok := us[r.URL]
	return ok
}

type URLPrefix string

func (up URLPrefix) Match(r *dto.Request) bool {
	return strings.HasPrefix(r.URL, string(up))
}

type URLSuffix string

func (up URLSuffix) Match(r *dto.Request) bool {
	return strings.HasSuffix(r.URL, string(up))
}

type URLKeyword string

func (uk URLKeyword) Match(r *dto.Request) bool {
	return strings.Contains(r.URL, string(uk))
}

type URLPrefixSet struct {
	trie trie.Trie
}

func (ups URLPrefixSet) Match(r *dto.Request) bool {
	return ups.trie.HasPrefixOf(r.URL)
}

// Status rules

type Status int

func (s Status) Match(r *dto.Request) bool {
	return s == Status(r.Status)
}

type StatusClass int

const (
	Informational StatusClass = 1
	Successful    StatusClass = 2
	Redirection   StatusClass = 3
	ClientError   StatusClass = 4
	ServerError   StatusClass = 5
)

func (sc StatusClass) Match(r *dto.Request) bool {
	return sc == StatusClass(r.Status/100)
}

// Sent rules

type SentMoreThan int64

func (smt SentMoreThan) Match(r *dto.Request) bool {
	return r.Sent > int64(smt)
}

type SentLessThan int64

func (slt SentLessThan) Match(r *dto.Request) bool {
	return r.Sent < int64(slt)
}

// Duration rules

type TookLongerThan time.Duration

func (tlt TookLongerThan) Match(r *dto.Request) bool {
	return r.Duration > time.Duration(tlt)
}

type TookShorterThan time.Duration

func (tst TookShorterThan) Match(r *dto.Request) bool {
	return r.Duration < time.Duration(tst)
}

// Host rules

type Host string

func (h Host) Match(r *dto.Request) bool {
	return h == Host(r.Host)
}

type HostSuffix string

func (hs HostSuffix) Match(r *dto.Request) bool {
	return strings.HasSuffix(r.Host, string(hs))
}

type HostKeyword string

func (hk HostKeyword) Match(r *dto.Request) bool {
	return strings.Contains(r.Host, string(hk))
}

// Agent rules

type Agent string

func (a Agent) Match(r *dto.Request) bool {
	return a == Agent(r.Agent)
}

type AgentKeyword string

func (ak AgentKeyword) Match(r *dto.Request) bool {
	return strings.Contains(r.Agent, string(ak))
}

type AgentSet map[string]struct{}

func (as AgentSet) Match(r *dto.Request) bool {
	_, ok := as[r.Agent]
	return ok
}
