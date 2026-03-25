package output

import (
	"net/netip"
	"time"
)

type OutputEntry struct {
	Time  time.Time
	Tag   string
	Host  netip.Addr
	Blame string
}
