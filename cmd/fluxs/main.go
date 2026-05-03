package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HT4w5/flux/pkg/api"
	"github.com/HT4w5/flux/pkg/config"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/engine"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
	"github.com/HT4w5/flux/pkg/jail/sqlite3"
	"github.com/HT4w5/flux/pkg/logsrc"
	"github.com/HT4w5/flux/pkg/logsrc/syslog"
	"github.com/HT4w5/flux/pkg/meta"
	"github.com/HT4w5/flux/pkg/parser"
	"github.com/HT4w5/flux/pkg/parser/nginx"
	"github.com/SladkyCitron/slogcolor"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
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
		jailInstance = sqlite3.New(
			sqlite3.WithDataSourceName(cfg.Jail.SQLite3.DataSource),
			sqlite3.WithPruneInterval(cfg.Jail.SQLite3.PruneInterval),
			sqlite3.WithBanDstPorts(cfg.Jail.SQLite3.BanDstPorts),
			sqlite3.WithLogger(logger),
		)
	default:
		logger.Error("unknown jail method", "method", cfg.Jail.Method)
		return false
	}

	// Create log source
	requestChan := make(chan dto.Request)
	defer close(requestChan)

	var logSource logsrc.LogSource
	switch cfg.LogSource.Method {
	case "syslog":
		if cfg.LogSource.Syslog.NumWorkers < 1 {
			cfg.LogSource.Syslog.NumWorkers = 1
		}

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
			syslog.WithNumWorkers(cfg.LogSource.Syslog.NumWorkers),
			syslog.WithRequestChan(requestChan),
			syslog.WithNetworkAddr(network, cfg.LogSource.Syslog.Addr),
			syslog.WithLogger(logger),
			syslog.WithParser(p),
		)
	default:
		logger.Error("unknown log source method", "method", cfg.LogSource.Method)
		return false
	}

	// Create RuleEngine
	if cfg.RuleEngine.MaxCacheBytes < 0 {
		cfg.RuleEngine.MaxCacheBytes = 1_000_000
	}

	re := engine.New(
		engine.WithFileSizeIndex(fileSizeIndex),
		engine.WithJail(jailInstance),
		engine.WithLogger(logger),
		engine.WithNumWorkers(cfg.RuleEngine.NumWorkers),
		engine.WithRequestChan(requestChan),
		engine.WithMaxCacheBytes(uint64(cfg.RuleEngine.MaxCacheBytes)),
	)

	apiHandler := api.New(
		api.WithRuleEngine(re),
		api.WithIndex(fileSizeIndex),
		api.WithJail(jailInstance),
		api.WithLogger(logger),
	)

	router := gin.New()
	router.Use(sloggin.NewWithConfig(logger, sloggin.Config{
		DefaultLevel:     slog.LevelInfo,
		ClientErrorLevel: slog.LevelWarn,
		ServerErrorLevel: slog.LevelError,
		HandleGinDebug:   true,
	}))
	router.Use(gin.Recovery())

	apiGrp := router.Group("/api")
	apiHandler.RegisterRoutes(router, apiGrp)

	if cfg.Web.PProf {
		pprof.Register(router)
	}

	if err := jailInstance.Start(); err != nil {
		logger.Error("failed to start jail", "error", err)
		return false
	}
	defer jailInstance.Close()

	if err := re.StartOrReload(cfg.RuleEngine.Chains); err != nil {
		logger.Error("failed to start RuleEngine", "error", err)
		return false
	}

	defer re.Shutdown()

	logSource.Start()
	defer logSource.Shutdown()

	// Start HTTP server
	httpServer := &http.Server{
		Addr:              cfg.Web.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	httpCtx, stopHTTP := context.WithCancel(ctx)
	defer stopHTTP()

	logger.Info("web server listening", "listen_addr", cfg.Web.ListenAddr)
	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed && err != nil {
			logger.Error("listen failed", "error", err)
			stopHTTP()
		}
	}()

	<-httpCtx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutdown failure", "error", err)
	}

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
