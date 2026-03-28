package jail

import (
	"context"

	"github.com/HT4w5/flux/pkg/dto"
)

// Jail stores ban entries and populate them to the output
type Jail interface {
	Init(ctx context.Context) error
	Close() error
	Add(ctx context.Context, b *dto.BanRecord) error
	Del(ctx context.Context, id int64) error
	List(ctx context.Context) ([]dto.BanRecord, error)
	Compile(ctx context.Context) ([]dto.BanRule, error)
}
