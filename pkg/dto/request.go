package dto

import (
	"net/netip"
	"time"
)

// Request entry
type Request struct {
	Time     time.Time
	Client   netip.Addr
	Server   netip.Addr
	Method   string
	URL      string
	Host     string
	Agent    string
	Status   int
	Sent     int64
	Duration time.Duration
}
