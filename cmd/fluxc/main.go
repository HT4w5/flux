package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HT4w5/flux/pkg/config"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/fw"
	"github.com/HT4w5/flux/pkg/fw/nft"
	"github.com/HT4w5/flux/pkg/fw/stub"
	"github.com/HT4w5/flux/pkg/meta"
	"github.com/SladkyCitron/slogcolor"
	"github.com/spf13/pflag"
)

func main() {
	var cfg config.ClientConfig
	var uiStr string
	pflag.StringVarP(&cfg.LogLevel, "log-level", "l", "info", "log level")
	pflag.StringVarP(&cfg.RuleEndpoint, "rule-endpoint", "e", "http://127.0.0.1/api/v1/rules", "rule api endpoint")
	pflag.StringVarP(&cfg.FirewallDriver, "firewall-driver", "f", "nftables", "firewall driver")
	pflag.StringVarP(&uiStr, "update-interval", "i", "10m", "update interval")
	pflag.BoolP("version", "v", false, "show version")
	pflag.BoolP("help", "h", false, "show help")
	pflag.Parse()

	if help, _ := pflag.CommandLine.GetBool("help"); help {
		fmt.Printf("Usage: %s [OPTIONS]\n", meta.ServerName)
		fmt.Println("Options:")
		pflag.PrintDefaults()
		os.Exit(0)
	}

	if version, _ := pflag.CommandLine.GetBool("version"); version {
		fmt.Println(meta.VersionString(meta.ServerName))
		os.Exit(0)
	}

	// Print banner
	meta.PrintBanner()
	meta.PrintlnBGBlue(meta.VersionString(meta.ServerName))
	fmt.Println()

	logger := setupLogger(cfg.LogLevel)

	var err error
	cfg.UpdateInterval, err = time.ParseDuration(uiStr)
	if err != nil {
		logger.Error("invalid update duration", "error", err)
	}
	//if cfg.UpdateInterval < time.Minute {
	//	cfg.UpdateInterval = time.Minute
	//}

	var fw fw.FirewallDriver
	switch cfg.FirewallDriver {
	case "nftables":
		fw = nft.New()
	case "stub":
		fw = &stub.StubDriver{}
	default:
		logger.Error("unsupported firewall driver", "driver", cfg.FirewallDriver)
		os.Exit(1)
	}

	// Test endpoint
	resp, err := http.Get(cfg.RuleEndpoint)
	if err != nil {
		logger.Error("endpoint unreachable", "error", err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		logger.Error("endpoint status not ok", "status", resp.StatusCode)
		os.Exit(1)
	}
	resp.Body.Close()

	ticker := time.NewTicker(cfg.UpdateInterval)
	defer ticker.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			err = fw.Reset()
			if err != nil {
				logger.Error("failed to reset firewall")
			}
			return
		case <-ticker.C:
			// Fetch rules
			resp, err := http.Get(cfg.RuleEndpoint)
			if err != nil {
				logger.Error("failed to fetch rules", "error", err)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				logger.Warn("fetch rules status not ok", "status", resp.StatusCode)
				continue
			}

			var rules []dto.BanRule
			dec := json.NewDecoder(resp.Body)
			err = dec.Decode(&rules)
			resp.Body.Close()
			if err != nil {
				logger.Error("failed to decode rules", "error", err)
				continue
			}

			// Install rules
			err = fw.Install(rules)
			if err != nil {
				logger.Error("failed to install rules", "error", err)
			}
		}
	}
}

func setupLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
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
