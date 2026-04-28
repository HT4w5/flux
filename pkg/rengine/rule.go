package rengine

import (
	"github.com/HT4w5/flux/pkg/dto"
)

type rule struct {
	statement   statement
	expressions []expression
}

func (r *rule) evaluate(ctx requestCtx, request *dto.Request) (end bool) {
	for _, e := range r.expressions {
		if !e.match(ctx, request) {
			return false
		}
	}
	return r.statement.execute(ctx, request)
}
