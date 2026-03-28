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
	pflag.StringP("config", "c", "", "config file path")
	pflag.StringP("log-level", "l", "", "log level (override config file)")
	pflag.BoolP("version", "v", false, "show version")
	pflag.BoolP("help", "h", false, "show help")
	pflag.Parse()

	if help, _ := pflag.CommandLine.GetBool("help"); help {
		fmt.Printf("Usage: %s [OPTIONS]\n", meta.Name)
		fmt.Println("Options:")
		pflag.PrintDefaults()
		os.Exit(0)
	}

	if version, _ := pflag.CommandLine.GetBool("version"); version {
		fmt.Println(meta.VersionLong)
		os.Exit(0)
	}

	// Print banner
	fmt.Println()
	printlnFGBlue(` ███████╗██╗     ██╗   ██╗██╗  ██╗`)
	printlnFGBlue(` ██╔════╝██║     ██║   ██║╚██╗██╔╝`)
	printlnFGBlue(` █████╗  ██║     ██║   ██║ ╚███╔╝ `)
	printlnFGBlue(` ██╔══╝  ██║     ██║   ██║ ██╔██╗ `)
	printlnFGBlue(` ██║     ███████╗╚██████╔╝██╔╝ ██╗`)
	printlnFGBlue(` ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝`)
	printlnFGBlue(` ────────────────────────────────►`)
	fmt.Print(" ")
	printlnBGBlue(meta.VersionLong)
	fmt.Println()

	cfg := config.Default()

	configPath, _ := pflag.CommandLine.GetString("config")
	if configPath != "" {
		if err := cfg.LoadFromPath(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config from %s: %v\n", configPath, err)
			os.Exit(1)
		}
	} else {
		if err := cfg.Load(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config, using defaults: %v\n", err)
		}
	}

	logLevel, _ := pflag.CommandLine.GetString("log-level")
	if logLevel != "" {
		cfg.Log.Level = logLevel
	}

	logger := setupLogger(cfg.Log.Level)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var p parser.Parser
	var err error
	switch cfg.LogSource.Parser {
	case "nginx":
		p, err = nginx.New()
		if err != nil {
			logger.Error("failed to create parser")
			os.Exit(1)
		}
	default:
		logger.Error("unknown parser", "parser", cfg.LogSource.Parser)
		os.Exit(1)
	}

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
			os.Exit(1)
		}

		logSource = syslog.New(
			syslog.WithNetworkAddr(network, cfg.LogSource.Syslog.Addr),
			syslog.WithLogger(logger),
			syslog.WithParser(p),
		)
	default:
		logger.Error("unknown log source method", "method", cfg.LogSource.Method)
		os.Exit(1)
	}

	fileSizeIndexOpts := []func(*index.FileSizeIndex){
		index.WithTTL(cfg.Index.TTL),
		index.WithmaxBytes(cfg.Index.MaxBytes),
		index.WithLogger(logger),
	}

	for tag, root := range cfg.Index.Routes {
		fileSizeIndexOpts = append(fileSizeIndexOpts, index.WithRoute(tag, root))
	}

	fileSizeIndex := index.New(fileSizeIndexOpts...)

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
			os.Exit(1)
		}
		jailInstance = j
		defer jailInstance.Close()
	default:
		logger.Error("unknown jail method", "method", cfg.Jail.Method)
		os.Exit(1)
	}

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
	}

	analyzer := analyzer.New(
		analyzer.WithLogSource(logSource),
		analyzer.WithIndex(fileSizeIndex),
		analyzer.WithJail(jailInstance),
		analyzer.WithLogger(logger),
		analyzer.WithConfig(analyzerConfig),
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

	<-ctx.Done()
	logger.Info("shutting down")

	apiServer.Shutdown()
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

func printlnFGBlue(str string) {
	fmt.Println("\x1b[0;34m" + str + "\x1b[0m")
}

func printlnBGBlue(str string) {
	fmt.Println("\x1b[44m" + str + "\x1b[0m")
}
