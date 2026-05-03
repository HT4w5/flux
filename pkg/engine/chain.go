package engine

import (
	"github.com/HT4w5/flux/pkg/dto"
)

type chain struct {
	name  string
	rules []rule
}

func (c *chain) traverse(ctx requestCtx, request *dto.Request) {
	for _, r := range c.rules {
		if r.evaluate(ctx, request) {
			break
		}
	}
}
