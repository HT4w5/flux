package logsrc

import (
	"context"

	"github.com/HT4w5/flux/pkg/dto"
)

type LogSource interface {
	Start(ctx context.Context, output chan<- dto.Request)
}
