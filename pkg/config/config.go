package config

import (
	"fmt"
	"time"

	"github.com/HT4w5/flux/pkg/meta"
	"github.com/docker/go-units"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type Config struct {
	Log       LogConfig       `mapstructure:"log"`
	LogSource LogSourceConfig `mapstructure:"log_source"`
	Index     IndexConfig     `mapstructure:"index"`
	Jail      JailConfig      `mapstructure:"jail"`
	Analyzer  AnalyzerConfig  `mapstructure:"analyzer"`
	API       APIConfig       `mapstructure:"api"`
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
	Network string `mapstructure:"network"`
	Addr    string `mapstructure:"addr"`
}

type IndexConfig struct {
	TTL      time.Duration     `mapstructure:"ttl"`
	MaxBytes int64             `mapstructure:"max_bytes"`
	Routes   map[string]string `mapstructure:"routes"`
}

type JailConfig struct {
	Method  string            `mapstructure:"method"`
	SQLite3 SQLite3JailConfig `mapstructure:"sqlite3"`
}

type SQLite3JailConfig struct {
	DataSource    string        `mapstructure:"data_source"`
	PruneInterval time.Duration `mapstructure:"prune_interval"`
	BanDstPorts   []uint16      `mapstructure:"ban_dst_ports"`
}

type AnalyzerConfig struct {
	RequestLeak          int           `mapstructure:"request_leak"`
	RequestVolume        int           `mapstructure:"request_volume"`
	RequestBanDuration   time.Duration `mapstructure:"request_ban_duration"`
	ByteLeak             int64         `mapstructure:"byte_leak"`
	ByteVolume           int64         `mapstructure:"byte_volume"`
	ByteBanDuration      time.Duration `mapstructure:"byte_ban_duration"`
	FileRatioLeak        int64         `mapstructure:"file_ratio_leak"`
	FileRatioVolume      int64         `mapstructure:"file_ratio_volume"`
	FileRatioBanDuration time.Duration `mapstructure:"file_ratio_ban_duration"`
	IPv4BanPrefixLen     int           `mapstructure:"ipv4_ban_prefix_length"`
	IPv6BanPrefixLen     int           `mapstructure:"ipv6_ban_prefix_length"`
	NumWorkers           int           `mapstructure:"num_workers"`
	MaxBytes             int64         `mapstructure:"max_bytes"`
}

type APIConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
}

func (cfg *Config) Load() error {
	vp := viper.New()
	vp.SetConfigName("config")
	vp.AddConfigPath(fmt.Sprintf("/etc/%s/", meta.Name))
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

func (cfg *Config) LoadFromPath(path string) error {
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

func Default() *Config {
	return &Config{
		Log: LogConfig{
			Level: "info",
		},
		LogSource: LogSourceConfig{
			Method: "syslog",
			Syslog: SyslogSourceConfig{
				Network: "udp",
				Addr:    "0.0.0.0:1514",
			},
		},
		Index: IndexConfig{
			TTL:      6 * time.Hour,
			MaxBytes: 1 * units.GiB,
			Routes:   make(map[string]string),
		},
		Jail: JailConfig{
			Method: "sqlite3",
			SQLite3: SQLite3JailConfig{
				DataSource:    "jail.db",
				PruneInterval: time.Hour,
				BanDstPorts:   []uint16{80, 443}, // HTTP and HTTPS
			},
		},
		Analyzer: AnalyzerConfig{
			RequestLeak:          10,
			RequestVolume:        50,
			RequestBanDuration:   24 * time.Hour,
			ByteLeak:             40 * units.MB,
			ByteVolume:           20 * units.GB,
			ByteBanDuration:      24 * time.Hour,
			FileRatioLeak:        5,
			FileRatioVolume:      5e5,
			FileRatioBanDuration: 7 * 24 * time.Hour,
			IPv4BanPrefixLen:     24,
			IPv6BanPrefixLen:     48,
			NumWorkers:           8,
			MaxBytes:             2 * units.GiB,
		},
		API: APIConfig{
			ListenAddr: ":80",
		},
	}
}
