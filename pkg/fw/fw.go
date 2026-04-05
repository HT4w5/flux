package fw

import "github.com/HT4w5/flux/pkg/dto"

type FirewallDriver interface {
	Install(rules []dto.BanRule) error
	Reset() error
}
