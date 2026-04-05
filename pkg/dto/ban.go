package dto

import (
	"net/netip"
	"time"
)

// Ban record stored in jail
type BanRecord struct {
	Prefix    netip.Prefix `json:"prefix"`
	ExpiresAt time.Time    `json:"expires_at"`
	Blame     string       `json:"blame"`
	ID        int64        `json:"id"`
}

// Ban rule compiled by jail
type BanRule struct {
	Prefixes []netip.Prefix `json:"prefixes"`
	DstPorts []uint16       `json:"dst_ports"`
}
