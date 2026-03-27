package syslog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/parser"
	"github.com/HT4w5/flux/pkg/parser/nginx"
	"gopkg.in/mcuadros/go-syslog.v2"
)

type Network int

const (
	TCP Network = iota
	UDP
	Unixgram
)

func (n Network) Name() string {
	switch n {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	case Unixgram:
		return "unixgram"
	default:
		return "unknown"
	}
}

var (
	ErrUnknownNetwork = errors.New("unknown network type")
)

// WithNetworkAddr sets the network type and address for the syslog server
func WithNetworkAddr(network Network, addr string) func(*SyslogSource) {
	return func(s *SyslogSource) {
		s.network = network
		s.addr = addr
	}
}

// WithLogger sets a custom logger for the syslog source
func WithLogger(logger *slog.Logger) func(*SyslogSource) {
	return func(s *SyslogSource) {
		s.logger = logger
	}
}

// WithParser sets a parser for parsing log lines
func WithParser(parser parser.Parser) func(*SyslogSource) {
	return func(s *SyslogSource) {
		s.parser = parser
	}
}

// Receive logs via a syslog server
type SyslogSource struct {
	srv          *syslog.Server
	logPartsChan syslog.LogPartsChannel
	logger       *slog.Logger
	parser       parser.Parser

	// Config
	network Network
	addr    string
}

func New(opts ...func(*SyslogSource)) *SyslogSource {
	s := &SyslogSource{
		logPartsChan: make(syslog.LogPartsChannel),
		logger:       slog.Default(),
		parser:       &nginx.NginxJSONParser{},
		network:      UDP,
		addr:         "0.0.0.0:514",
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create syslog server
	handler := syslog.NewChannelHandler(s.logPartsChan)
	s.srv = syslog.NewServer()
	s.srv.SetFormat(syslog.Automatic)
	s.srv.SetHandler(handler)
	return s
}

func (s *SyslogSource) Start(ctx context.Context, output chan<- dto.Request) {
	go func() {
		s.run(ctx, output)
	}()
}

func (s *SyslogSource) run(ctx context.Context, output chan<- dto.Request) {
	// Start syslog server
	var err error
	switch s.network {
	case TCP:
		err = s.srv.ListenTCP(s.addr)
	case UDP:
		err = s.srv.ListenUDP(s.addr)
	case Unixgram:
		err = s.srv.ListenUnixgram(s.addr)
	default:
		err = ErrUnknownNetwork
	}

	if err != nil {
		s.logger.Error("failed to start syslog server", "error", err, "network", s.network.Name(), "addr", s.addr)
		return
	}

	s.logger.Info("syslog server started", "network", s.network.Name(), "addr", s.addr)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("syslog server shutdown")
			if err := s.srv.Kill(); err != nil {
				s.logger.Error("failed to stop syslog server", "error", err)
			}
			return
		case logPart := <-s.logPartsChan:
			if logPart == nil {
				s.logger.Error("syslog server died", "error", s.srv.GetLastError())
				return
			}
			line, ok := logPart["content"].(string)
			if !ok {
				line, ok = logPart["message"].(string)
				if !ok {
					s.logger.Error("failed to unpack line, couldn't match field")
					continue
				}
			}
			s.logger.Debug("line received", "content", line)
			req, err := s.parser.Parse([]byte(line))
			if err != nil {
				s.logger.Warn("failed to parse line", "line", fmt.Sprintf("%.10s", line))
				continue
			}
			output <- req
		}
	}
}
