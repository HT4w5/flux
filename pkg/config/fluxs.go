package config

import (
	"fmt"
	"time"

	"github.com/HT4w5/flux/pkg/engine"
	"github.com/HT4w5/flux/pkg/meta"
	"github.com/docker/go-units"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type ServerConfig struct {
	LogSource  LogSourceConfig  `mapstructure:"log_source"`
	Log        LogConfig        `mapstructure:"log"`
	Web        WebConfig        `mapstructure:"web"`
	Index      IndexConfig      `mapstructure:"index"`
	Jail       JailConfig       `mapstructure:"jail"`
	RuleEngine RuleEngineConfig `mapstructure:"rule_engine"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

type LogSourceConfig struct {
	Method string             `mapstructure:"method"`
	Parser string             `mapstructure:"parser"`
	Syslog SyslogSourceConfig `mapstructure:"syslog"`
}

type SyslogSourceConfig struct {
	Network    string `mapstructure:"network"`
	Addr       string `mapstructure:"addr"`
	NumWorkers int    `mapstructure:"num_workers"`
}

type IndexConfig struct {
	Routes   map[string]string `mapstructure:"routes"`
	TTL      time.Duration     `mapstructure:"ttl"`
	MaxBytes int64             `mapstructure:"max_bytes"`
}

type JailConfig struct {
	Method              string            `mapstructure:"method"`
	SQLite3             SQLite3JailConfig `mapstructure:"sqlite3"`
	IPv4BanPrefixLength int               `mapstructure:"ipv4_ban_prefix_length"`
	IPv6BanPrefixLength int               `mapstructure:"ipv6_ban_prefix_length"`
}

type SQLite3JailConfig struct {
	DataSource    string        `mapstructure:"data_source"`
	BanDstPorts   []uint16      `mapstructure:"ban_dst_ports"`
	PruneInterval time.Duration `mapstructure:"prune_interval"`
}

type RuleEngineConfig struct {
	Chains        []engine.ChainConfig `mapstructure:"chains"`
	MaxCacheBytes int64                `mapstructure:"max_cache_bytes"`
	NumWorkers    int                  `mapstructure:"num_workers"`
}

type WebConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
	PProf      bool   `mapstructure:"pprof"`
}

func (cfg *ServerConfig) Load() error {
	vp := viper.New()
	vp.SetConfigName("config")
	vp.AddConfigPath(fmt.Sprintf("/etc/%s/", meta.ServerName))
	vp.AddConfigPath(".")

	err := vp.ReadInConfig()
	if err != nil {
		return err
	}

	return vp.Unmarshal(cfg, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			ByteSizeHookFunc(),
		),
	))
}

func (cfg *ServerConfig) LoadFromPath(path string) error {
	vp := viper.New()
	vp.SetConfigFile(path)

	err := vp.ReadInConfig()
	if err != nil {
		return err
	}

	return vp.Unmarshal(cfg, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			ByteSizeHookFunc(),
		),
	))
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Log: LogConfig{
			Level: "info",
		},
		LogSource: LogSourceConfig{
			Method: "syslog",
			Parser: "nginx",
			Syslog: SyslogSourceConfig{
				Network:    "udp",
				Addr:       "0.0.0.0:1514",
				NumWorkers: 8,
			},
		},
		Index: IndexConfig{
			TTL:      6 * time.Hour,
			MaxBytes: 1 * units.GiB,
			Routes:   make(map[string]string),
		},
		Jail: JailConfig{
			Method:              "sqlite3",
			IPv4BanPrefixLength: 24,
			IPv6BanPrefixLength: 48,
			SQLite3: SQLite3JailConfig{
				DataSource:    "jail.db",
				PruneInterval: time.Hour,
				BanDstPorts:   []uint16{80, 443}, // HTTP and HTTPS
			},
		},
		RuleEngine: RuleEngineConfig{
			MaxCacheBytes: 200_000_000,
			NumWorkers:    8,
		},
		Web: WebConfig{
			ListenAddr: ":8080",
			PProf:      false,
		},
	}
}
