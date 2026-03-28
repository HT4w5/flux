package dto

import (
	"net/netip"
	"time"
)

// Ban record stored in jail
type BanRecord struct {
	ID        int64        `json:"id"`
	Prefix    netip.Prefix `json:"prefix"`
	Blame     string       `json:"blame"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// Ban rule compiled by jail
type BanRule struct {
	Prefixes []netip.Prefix `json:"prefixes"`
	DstPorts []uint16       `json:"dst_ports"`
}
