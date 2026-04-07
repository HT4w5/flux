package dto

import (
	"net/netip"
	"time"
)

// Ban record stored in jail
type BanRecord struct {
	Addr      netip.Addr `json:"addr"`
	ExpiresAt time.Time  `json:"expires_at"`
	Blame     string     `json:"blame"`
}

// Ban rule compiled by jail
type BanRule struct {
	Prefixes []netip.Prefix `json:"prefixes"`
	DstPorts []uint16       `json:"dst_ports"`
}
