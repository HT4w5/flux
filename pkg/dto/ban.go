package dto

import (
	"net/netip"
	"time"
)

// Ban entry
type Ban struct {
	ID        int64
	Prefix    netip.Prefix
	Blame     string
	ExpiresAt time.Time
}
