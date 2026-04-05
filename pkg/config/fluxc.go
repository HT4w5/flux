package config

import (
	"time"
)

type ClientConfig struct {
	LogLevel       string
	RuleEndpoint   string
	FirewallDriver string
	UpdateInterval time.Duration
}
