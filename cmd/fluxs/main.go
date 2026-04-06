package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HT4w5/flux/pkg/analyzer"
	"github.com/HT4w5/flux/pkg/api"
	"github.com/HT4w5/flux/pkg/config"
	"github.com/HT4w5/flux/pkg/filter"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
	"github.com/HT4w5/flux/pkg/jail/sqlite3"
	"github.com/HT4w5/flux/pkg/logsrc"
	"github.com/HT4w5/flux/pkg/logsrc/syslog"
	"github.com/HT4w5/flux/pkg/meta"
	"github.com/HT4w5/flux/pkg/parser"
	"github.com/HT4w5/flux/pkg/parser/nginx"
	"github.com/SladkyCitron/slogcolor"
	"github.com/gin-gonic/gin"
	"github.com/spf13/pflag"
)

func main() {
	ok := entryPoint()
	if !ok {
		os.Exit(1)
	}
}

func entryPoint() bool {
	pflag.StringP("config", "c", "", "config file path")
	pflag.StringP("log-level", "l", "", "log level (override config file)")
	pflag.BoolP("version", "v", false, "show version")
	pflag.BoolP("help", "h", false, "show help")
	pflag.Parse()

	if help, _ := pflag.CommandLine.GetBool("help"); help {
		fmt.Printf("Usage: %s [OPTIONS]\n", meta.ServerName)
		fmt.Println("Options:")
		pflag.PrintDefaults()
		return true
	}

	if version, _ := pflag.CommandLine.GetBool("version"); version {
		fmt.Println(meta.VersionString(meta.ServerName))
		return true
	}

	// Print banner
	meta.PrintBanner()
	meta.PrintlnBGBlue(meta.VersionString(meta.ServerName))
	fmt.Println()

	// Load config
	cfg := config.DefaultServerConfig()

	configPath, _ := pflag.CommandLine.GetString("config")
	if configPath != "" {
		if err := cfg.LoadFromPath(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config from %s: %v\n", configPath, err)
			return false
		}
	} else {
		if err := cfg.Load(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config, using defaults: %v\n", err)
		}
	}

	// Set up logger
	logLevel, _ := pflag.CommandLine.GetString("log-level")
	if logLevel != "" {
		cfg.Log.Level = logLevel
	}

	logger := setupLogger(cfg.Log.Level)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Create parser
	var p parser.Parser
	var err error
	switch cfg.LogSource.Parser {
	case "nginx":
		p, err = nginx.New()
		if err != nil {
			logger.Error("failed to create parser")
			return false
		}
	default:
		logger.Error("unknown parser", "parser", cfg.LogSource.Parser)
		return false
	}

	// Create log source
	var logSource logsrc.LogSource
	switch cfg.LogSource.Method {
	case "syslog":
		var network syslog.Network
		switch cfg.LogSource.Syslog.Network {
		case "tcp":
			network = syslog.TCP
		case "udp":
			network = syslog.UDP
		case "unixgram":
			network = syslog.Unixgram
		default:
			logger.Error("unknown syslog network", "network", cfg.LogSource.Syslog.Network)
			return false
		}

		logSource = syslog.New(
			syslog.WithNetworkAddr(network, cfg.LogSource.Syslog.Addr),
			syslog.WithLogger(logger),
			syslog.WithParser(p),
		)
	default:
		logger.Error("unknown log source method", "method", cfg.LogSource.Method)
		return false
	}

	// Create file size index
	fileSizeIndexOpts := []func(*index.FileSizeIndex){
		index.WithTTL(cfg.Index.TTL),
		index.WithmaxBytes(cfg.Index.MaxBytes),
		index.WithLogger(logger),
	}

	for tag, root := range cfg.Index.Routes {
		fileSizeIndexOpts = append(fileSizeIndexOpts, index.WithRoute(tag, root))
	}

	fileSizeIndex := index.New(fileSizeIndexOpts...)

	// Create jail
	var jailInstance jail.Jail
	switch cfg.Jail.Method {
	case "sqlite3":
		j := sqlite3.New(
			sqlite3.WithDataSourceName(cfg.Jail.SQLite3.DataSource),
			sqlite3.WithPruneInterval(cfg.Jail.SQLite3.PruneInterval),
			sqlite3.WithBanDstPorts(cfg.Jail.SQLite3.BanDstPorts),
			sqlite3.WithLogger(logger),
		)
		if err := j.Init(ctx); err != nil {
			logger.Error("failed to initialize jail", "error", err)
			return false
		}
		jailInstance = j
		defer jailInstance.Close()
	default:
		logger.Error("unknown jail method", "method", cfg.Jail.Method)
		return false
	}

	// Build filter
	var f filter.FilterRule
	if cfg.Analyzer.IngressFilter != nil {
		f, err = filter.Build(cfg.Analyzer.IngressFilter)
		if err != nil {
			logger.Error("failed to build filter", "error", err)
			return false
		}
	} else {
		f = filter.None{}
	}

	var cbf filter.FilterRule
	if cfg.Analyzer.ClientBucketFilter != nil {
		cbf, err = filter.Build(cfg.Analyzer.ClientBucketFilter)
		if err != nil {
			logger.Error("failed to build filter", "error", err)
			return false
		}
	} else {
		cbf = filter.All{}
	}

	var cpbf filter.FilterRule
	if cfg.Analyzer.ClientPathBucketFilter != nil {
		cpbf, err = filter.Build(cfg.Analyzer.ClientPathBucketFilter)
		if err != nil {
			logger.Error("failed to build filter", "error", err)
			return false
		}
	} else {
		cpbf = filter.All{}
	}

	var filterMode analyzer.FilterMode
	switch cfg.Analyzer.IngressFilterMode {
	case "whitelist":
		filterMode = analyzer.Whitelist
	case "blacklist":
		filterMode = analyzer.Blacklist
	default:
		logger.Error("unknown filter mode", "mode", cfg.Analyzer.IngressFilter)
		return false
	}

	// Create analyzer
	analyzerConfig := analyzer.Config{
		RequestLeak:          cfg.Analyzer.RequestLeak,
		RequestVolume:        cfg.Analyzer.RequestVolume,
		RequestBanDuration:   cfg.Analyzer.RequestBanDuration,
		ByteLeak:             cfg.Analyzer.ByteLeak,
		ByteVolume:           cfg.Analyzer.ByteVolume,
		ByteBanDuration:      cfg.Analyzer.ByteBanDuration,
		FileRatioLeak:        cfg.Analyzer.FileRatioLeak,
		FileRatioVolume:      cfg.Analyzer.FileRatioVolume,
		FileRatioBanDuration: cfg.Analyzer.FileRatioBanDuration,
		IPv4BanPrefixLen:     cfg.Analyzer.IPv4BanPrefixLen,
		IPv6BanPrefixLen:     cfg.Analyzer.IPv6BanPrefixLen,
		NumWorkers:           cfg.Analyzer.NumWorkers,
		MaxBytes:             cfg.Analyzer.MaxBytes,
		FilterMode:           filterMode,
	}

	analyzer := analyzer.New(
		analyzer.WithLogSource(logSource),
		analyzer.WithIndex(fileSizeIndex),
		analyzer.WithJail(jailInstance),
		analyzer.WithLogger(logger),
		analyzer.WithConfig(analyzerConfig),
		analyzer.WithIngressFilter(f),
		analyzer.WithClientBucketFilter(cbf),
		analyzer.WithClientPathBucketFilter(cpbf),
	)

	apiServer := api.New(
		api.WithAnalyzer(analyzer),
		api.WithIndex(fileSizeIndex),
		api.WithJail(jailInstance),
		api.WithLogger(logger),
		api.WithListenAddr(cfg.API.ListenAddr),
	)

	analyzer.Start(ctx)
	apiServer.Start()
	defer apiServer.Shutdown()

	<-ctx.Done()
	logger.Info("shutting down")

	return true
}

func setupLogger(level string) *slog.Logger {
	var logLevel slog.Level
	gin.SetMode(gin.ReleaseMode)
	switch level {
	case "debug":
		gin.SetMode(gin.DebugMode)
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	return slog.New(slogcolor.NewHandler(os.Stdout, &slogcolor.Options{
		Level:         logLevel,
		TimeFormat:    time.RFC3339,
		SrcFileMode:   slogcolor.ShortFile,
		SrcFileLength: 20,
	}))
}
