package nginx

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
	"unsafe"

	"github.com/bytedance/sonic"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/HT4w5/flux/pkg/dto"
)

const (
	nsPerS = 1e9
)

type nginxJSONLogEntry struct {
	Time     sonic.NoCopyRawMessage `json:"time"` // $msec format: "1734345934.123"
	Client   sonic.NoCopyRawMessage `json:"client"`
	Server   sonic.NoCopyRawMessage `json:"server"`
	Method   sonic.NoCopyRawMessage `json:"method"`
	URL      sonic.NoCopyRawMessage `json:"url"`
	Status   int                    `json:"status"`
	Sent     int64                  `json:"sent"`
	Duration sonic.NoCopyRawMessage `json:"duration"`
	Host     sonic.NoCopyRawMessage `json:"host"`
	Agent    sonic.NoCopyRawMessage `json:"agent"`
}

type NginxJSONParser struct {
	decoder   json.Decoder
	methodLRU *lru.TwoQueueCache[string, string]
	urlLRU    *lru.TwoQueueCache[string, string]
	hostLRU   *lru.TwoQueueCache[string, string]
	agentLRU  *lru.TwoQueueCache[string, string]
}

func (p *NginxJSONParser) Parse(line []byte) (dto.Request, error) {
	var logEntry nginxJSONLogEntry
	err := sonic.Unmarshal(line, &logEntry)
	if err != nil {
		return dto.Request{}, err
	}

	r := dto.Request{
		Method: internMethod(logEntry.Method),
		URL:    internString(p.urlLRU, logEntry.URL),
		Status: logEntry.Status,
		Sent:   logEntry.Sent,
		Host:   internString(p.hostLRU, logEntry.Host),
		Agent:  internString(p.agentLRU, logEntry.Agent),
	}

	r.Time, err = parseNginxTime(logEntry.Time)
	err = r.Client.UnmarshalText(logEntry.Client)
	if err != nil {
		return dto.Request{}, err
	}
	err = r.Server.UnmarshalText(logEntry.Server)
	if err != nil {
		return dto.Request{}, err
	}
	r.Duration, err = parseNginxDuration(logEntry.Duration)

	return r, nil
}

// Intern helpers
func internString(lru *lru.TwoQueueCache[string, string], b []byte) string {
	lookupKey := unsafe.String(unsafe.SliceData(b), len(b))
	// Cache hit
	if val, ok := lru.Get(lookupKey); ok {
		return val
	}

	// Cache miss, make copy
	permString := string(b)
	lru.Add(permString, permString)
	return permString
}

var commonMethods = map[string]string{
	"GET":     "GET",
	"HEAD":    "HEAD",
	"POST":    "POST",
	"PUT":     "PUT",
	"DELETE":  "DELETE",
	"CONNECT": "CONNECT",
	"OPTIONS": "OPTIONS",
	"TRACE":   "TRACE",
	"PATCH":   "PATCH",
}

func internMethod(b []byte) string {
	s := unsafe.String(unsafe.SliceData(b), len(b))
	if val, ok := commonMethods[s]; ok {
		return val
	}
	return string(b) // Fallback for uncommon methods
}

// Parser helpers

var pow10 = [10]int64{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000}

func parseNginxDuration(b []byte) (time.Duration, error) {
	dotIdx := bytes.IndexByte(b, '.')
	if dotIdx < 0 {
		sec, err := strconv.ParseInt(unsafe.String(&b[0], len(b)), 10, 64)
		return time.Duration(sec * nsPerS), err
	}

	// Parse seconds (Unix Epoch)
	sec, err := strconv.ParseInt(unsafe.String(&b[0], dotIdx), 10, 64)
	if err != nil {
		return 0, err
	}

	// Parse milliseconds/microseconds
	fracBytes := b[dotIdx+1:]
	frac, err := strconv.ParseInt(unsafe.String(&fracBytes[0], len(fracBytes)), 10, 64)
	if err != nil {
		return 0, err
	}

	// Convert fraction to nanoseconds
	nsec := (frac * 1e9) / pow10[len(fracBytes)]

	return time.Duration(sec*nsPerS + nsec), nil
}

func parseNginxTime(b []byte) (time.Time, error) {
	dotIdx := bytes.IndexByte(b, '.')
	if dotIdx < 0 {
		sec, err := strconv.ParseInt(unsafe.String(&b[0], len(b)), 10, 64)
		return time.Unix(sec, 0), err
	}

	// Parse seconds (Unix Epoch)
	sec, err := strconv.ParseInt(unsafe.String(&b[0], dotIdx), 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	// Parse milliseconds/microseconds
	fracBytes := b[dotIdx+1:]
	frac, err := strconv.ParseInt(unsafe.String(&fracBytes[0], len(fracBytes)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	// Convert fraction to nanoseconds
	nsec := (frac * nsPerS) / pow10[len(fracBytes)]

	return time.Unix(sec, nsec), nil
}
