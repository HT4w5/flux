package parser

import (
	"github.com/HT4w5/flux/pkg/dto"
)

// Parser parse a line of log into a dto.Request
type Parser interface {
	Parse(line []byte) (dto.Request, error)
}
