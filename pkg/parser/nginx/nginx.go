package nginx

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	json "github.com/bytedance/sonic"

	"github.com/HT4w5/flux/pkg/dto"
)

const (
	nsPerS = 1000000000
)

type nginxJSONLogEntry struct {
	Time     string `json:"time"` // $msec format: "1734345934.123"
	Client   string `json:"client"`
	Server   string `json:"server"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Sent     int64  `json:"sent"`
	Duration string `json:"duration"`
	Host     string `json:"host"`
	Agent    string `json:"agent"`
}

type NginxJSONParser struct{}

func (p *NginxJSONParser) Parse(line []byte) (dto.Request, error) {
	var logEntry nginxJSONLogEntry
	err := json.Unmarshal(line, &logEntry)
	if err != nil {
		return dto.Request{}, err
	}

	r := dto.Request{
		Method: logEntry.Method,
		URL:    logEntry.URL,
		Status: logEntry.Status,
		Sent:   logEntry.Sent,
		Host:   logEntry.Host,
		Agent:  logEntry.Agent,
	}

	r.Time, err = parseNginxTime(logEntry.Time)
	r.Client, err = netip.ParseAddr(logEntry.Client)
	if err != nil {
		return dto.Request{}, err
	}
	r.Server, err = netip.ParseAddr(logEntry.Server)
	if err != nil {
		return dto.Request{}, err
	}
	r.Duration, err = parseNginxDuration(logEntry.Duration)

	return r, nil
}

func parseNginxTime(tStr string) (time.Time, error) {
	dotIdx := strings.IndexByte(tStr, '.')
	if dotIdx < 0 {
		return time.Time{}, fmt.Errorf("bad time format")
	}

	i, err := strconv.ParseInt(tStr[:dotIdx], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	fStr := tStr[dotIdx+1:]
	f, err := strconv.ParseInt(fStr, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(i, f*nsPerS/int64(math.Pow10(len(fStr)))), nil
}

func parseNginxDuration(dStr string) (time.Duration, error) {
	dotIdx := strings.IndexByte(dStr, '.')
	if dotIdx < 0 {
		return 0, fmt.Errorf("bad duration format")
	}

	i, err := strconv.ParseInt(dStr[:dotIdx], 10, 64)
	if err != nil {
		return 0, err
	}
	fStr := dStr[dotIdx+1:]
	f, err := strconv.ParseInt(fStr, 10, 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(i*nsPerS + f*nsPerS/int64(math.Pow10(len(fStr)))), nil
}
