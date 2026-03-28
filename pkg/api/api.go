package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/HT4w5/flux/pkg/analyzer"
	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
	"github.com/gin-gonic/gin"

	sloggin "github.com/samber/slog-gin"
)

type msgResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

type APIServer struct {
	// External
	analyzer *analyzer.Analyzer
	index    *index.FileSizeIndex
	jail     jail.Jail
	logger   *slog.Logger

	// Internal
	srv    *http.Server
	router *gin.Engine

	// Config
	listenAddr string
}

func New(opts ...func(*APIServer)) *APIServer {
	s := &APIServer{
		logger:     slog.New(slog.DiscardHandler),
		router:     gin.New(),
		listenAddr: ":80",
	}

	for _, opt := range opts {
		opt(s)
	}

	// Configure router
	s.router.Use(sloggin.NewWithConfig(s.logger, sloggin.Config{
		DefaultLevel:     slog.LevelInfo,
		ClientErrorLevel: slog.LevelWarn,
		ServerErrorLevel: slog.LevelError,
		HandleGinDebug:   true,
	}))
	s.router.Use(gin.Recovery())

	// Setup routes
	// api
	api := s.router.Group("api")
	// v1
	{
		v1 := api.Group("/v1")
		v1.GET("/ping", handlePing)
		v1.GET("/records", s.handleGETBanRecords)
		v1.POST("/records", s.handlePOSTBanRecord)
		v1.DELETE("/records", s.handleDELETEBanRecord)
		v1.GET("/rules", s.handleGETBanRules)
		v1.GET("/stats/analyzer", s.handleGETAnalyzerStats)
		v1.GET("/stats/index", s.handleGETIndexStats)
	}

	s.srv = &http.Server{
		Addr:              s.listenAddr,
		Handler:           s.router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}

func (s *APIServer) Start() {
	s.logger.Info("starting")
	go func() {
		if err := s.srv.ListenAndServe(); err != http.ErrServerClosed && err != nil {
			s.logger.Error("listen failed", "error", err)
		}
	}()
}

func (s *APIServer) Shutdown() {
	s.logger.Info("shutdown")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	if err != nil {
		s.logger.Warn("shutdown failure", "error", err)
	}
}

// Ban info handlers

func (s *APIServer) handleGETBanRecords(c *gin.Context) {
	recs, err := s.jail.List(c.Request.Context())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, recs)
}

func (s *APIServer) handlePOSTBanRecord(c *gin.Context) {
	var rec dto.BanRecord
	if err := c.ShouldBindJSON(&rec); err != nil {
		c.JSON(http.StatusBadRequest, msgResp{
			Code: http.StatusBadRequest,
			Msg:  err.Error(),
		})
		return
	}

	if err := s.jail.Add(c.Request.Context(), &rec); err != nil {
		c.JSON(http.StatusInternalServerError, msgResp{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, msgResp{
		Code: http.StatusOK,
		Msg:  "success",
	})
}

type deleteRequest struct {
	id int64 `form:"id" binding:"required,gt=0"`
}

func (s *APIServer) handleDELETEBanRecord(c *gin.Context) {
	var req deleteRequest

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, msgResp{
			Code: http.StatusBadRequest,
			Msg:  err.Error(),
		})
		return
	}

	if err := s.jail.Del(c.Request.Context(), req.id); err != nil {
		c.JSON(http.StatusInternalServerError, msgResp{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, msgResp{
		Code: http.StatusOK,
		Msg:  "success",
	})
}

func (s *APIServer) handleGETBanRules(c *gin.Context) {
	rules, err := s.jail.Compile(c.Request.Context())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, rules)
}

// Analyzer handlers

func (s *APIServer) handleGETAnalyzerStats(c *gin.Context) {
	stats := s.analyzer.GetStats()
	c.JSON(http.StatusOK, stats)
}

// Index handlers

func (s *APIServer) handleGETIndexStats(c *gin.Context) {
	stats := s.index.GetStats()
	c.JSON(http.StatusOK, stats)
}

func handlePing(c *gin.Context) {
	c.JSON(http.StatusOK, msgResp{
		Code: http.StatusOK,
		Msg:  "pong",
	})
}

// Options
func WithAnalyzer(a *analyzer.Analyzer) func(*APIServer) {
	return func(s *APIServer) {
		s.analyzer = a
	}
}

func WithIndex(i *index.FileSizeIndex) func(*APIServer) {
	return func(s *APIServer) {
		s.index = i
	}
}

func WithJail(j jail.Jail) func(*APIServer) {
	return func(s *APIServer) {
		s.jail = j
	}
}

func WithLogger(l *slog.Logger) func(*APIServer) {
	return func(s *APIServer) {
		s.logger = l
	}
}

func WithListenAddr(addr string) func(*APIServer) {
	return func(s *APIServer) {
		s.listenAddr = addr
	}
}
