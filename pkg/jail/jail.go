package jail

import (
	"context"
	"net/netip"

	"github.com/HT4w5/flux/pkg/dto"
)

// Jail stores ban entries and populate them to the output
type Jail interface {
	Init(ctx context.Context) error
	Close() error
	Add(ctx context.Context, b *dto.BanRecord) error
	Del(ctx context.Context, addr netip.Addr) error
	List(ctx context.Context) ([]dto.BanRecord, error)
	Compile(ctx context.Context) ([]dto.BanRule, error)
}
