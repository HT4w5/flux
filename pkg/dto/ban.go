package dto

import "net/netip"

// Ban entry
type Ban struct {
	Prefix netip.Prefix
	Blame  string
}
