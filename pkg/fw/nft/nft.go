package nft

import (
	"encoding/binary"
	"log/slog"
	"net/netip"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

const (
	tableName = "fluxc"
	chainName = "prerouting_filter"
)

type NFTablesDriver struct {
	excludes []netip.Prefix
	logger   *slog.Logger
}

type Option func(*NFTablesDriver)

func New(opts ...Option) *NFTablesDriver {
	d := &NFTablesDriver{
		excludes: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("fe80::/10"),
		},
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

func WithLogger(l *slog.Logger) Option {
	return func(nd *NFTablesDriver) {
		nd.logger = l
	}
}

func WithExcludePrivate() Option {
	return func(nd *NFTablesDriver) {
		nd.excludes = append(nd.excludes, netip.MustParsePrefix("10.0.0.0/8"))
		nd.excludes = append(nd.excludes, netip.MustParsePrefix("172.16.0.0/12"))
		nd.excludes = append(nd.excludes, netip.MustParsePrefix("192.168.0.0/16"))
		nd.excludes = append(nd.excludes, netip.MustParsePrefix("fc00::/7"))
	}
}

func WithExcludePrefix(prefix netip.Prefix) Option {
	return func(nd *NFTablesDriver) {
		nd.excludes = append(nd.excludes, prefix)
	}
}

func (d *NFTablesDriver) Install(rules []dto.BanRule) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	}

	conn.DelTable(table)

	conn.Flush()

	table = conn.AddTable(table)

	chain := conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRaw,
	})

	for i, r := range rules {
		var ipsbV4 netipx.IPSetBuilder
		var ipsbV6 netipx.IPSetBuilder

		for _, p := range r.Prefixes {
			if p.Addr().Is4() {
				ipsbV4.AddPrefix(p)
			} else {
				ipsbV6.AddPrefix(p)
			}
		}

		for _, p := range d.excludes {
			if p.Addr().Is4() {
				ipsbV4.RemovePrefix(p)
			} else {
				ipsbV6.RemovePrefix(p)
			}
		}

		setV4, err := ipsbV4.IPSet()
		if err != nil {
			return err
		}

		setV6, err := ipsbV6.IPSet()
		if err != nil {
			return err
		}

		var elemsV4 []nftables.SetElement
		for _, r := range setV4.Ranges() {
			elemsV4 = append(
				elemsV4,
				nftables.SetElement{Key: r.From().AsSlice()},
				nftables.SetElement{Key: r.To().Next().AsSlice(), IntervalEnd: true},
			)
		}

		var elemsV6 []nftables.SetElement
		for _, r := range setV6.Ranges() {
			elemsV6 = append(
				elemsV6,
				nftables.SetElement{Key: r.From().AsSlice()},
				nftables.SetElement{Key: r.To().Next().AsSlice(), IntervalEnd: true},
			)
		}

		var elemsPorts []nftables.SetElement
		for _, p := range r.DstPorts {
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, p)

			elemsPorts = append(elemsPorts, nftables.SetElement{
				Key: portBuf,
			})
		}

		if err := conn.AddSet(
			&nftables.Set{
				Table:    table,
				KeyType:  nftables.TypeIPAddr,
				Name:     v4SetName(i),
				Interval: true,
			},
			elemsV4,
		); err != nil {
			return err
		}

		if err := conn.AddSet(
			&nftables.Set{
				Table:    table,
				KeyType:  nftables.TypeIP6Addr,
				Name:     v6SetName(i),
				Interval: true,
			},
			elemsV6,
		); err != nil {
			return err
		}

		if err := conn.AddSet(
			&nftables.Set{
				Table:   table,
				KeyType: nftables.TypeInetService,
				Name:    portSetName(i),
			},
			elemsPorts,
		); err != nil {
			return err
		}

		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				// IPv4
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				// Addr
				&expr.Payload{
					DestRegister:  1,
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
					Offset:        12, // IPv4 Source Offset
					Len:           4,
				},
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        v4SetName(i),
				},
				// Port
				&expr.Payload{
					DestRegister:  1,
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseTransportHeader,
					Offset:        2, // TCP/UDP Dest Port Offset
					Len:           2,
				},
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        portSetName(i),
				},
				// Drop
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})

		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				// IPv6
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
				// Addr
				&expr.Payload{
					DestRegister:  1,
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
					Offset:        8,
					Len:           16,
				},
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        v6SetName(i),
				},
				// Port
				&expr.Payload{
					DestRegister:  1,
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseTransportHeader,
					Offset:        2, // TCP/UDP Dest Port Offset
					Len:           2,
				},
				&expr.Lookup{
					SourceRegister: 1,
					SetName:        portSetName(i),
				},
				// Drop
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	return conn.Flush()
}

func (d *NFTablesDriver) Reset() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	conn.DelTable(&nftables.Table{
		Name: tableName,
	})
	return conn.Flush()
}
