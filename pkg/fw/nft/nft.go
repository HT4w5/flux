package nft

import (
	"encoding/binary"
	"log/slog"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

const (
	tableName = "fluxc"
	chainName = "input_filter"
)

type NFTablesDriver struct {
	logger *slog.Logger
}

func New(opts ...func(*NFTablesDriver)) *NFTablesDriver {
	d := &NFTablesDriver{}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

func WithLogger(l *slog.Logger) func(*NFTablesDriver) {
	return func(nd *NFTablesDriver) {
		nd.logger = l
	}
}

func (d *NFTablesDriver) Install(rules []dto.BanRule) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	conn.DelTable(&nftables.Table{
		Name: tableName,
	})

	conn.Flush()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
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
				nftables.SetElement{Key: r.To().AsSlice(), IntervalEnd: true},
			)
		}

		var elemsV6 []nftables.SetElement
		for _, r := range setV6.Ranges() {
			elemsV6 = append(
				elemsV6,
				nftables.SetElement{Key: r.From().AsSlice()},
				nftables.SetElement{Key: r.To().AsSlice(), IntervalEnd: true},
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
