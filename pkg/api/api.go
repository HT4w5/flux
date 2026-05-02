package api

import (
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/HT4w5/flux/pkg/dto"
	"github.com/HT4w5/flux/pkg/index"
	"github.com/HT4w5/flux/pkg/jail"
	"github.com/HT4w5/flux/pkg/rengine"
	"github.com/gin-gonic/gin"
)

type msgResp struct {
	Msg  string `json:"msg"`
	Code int    `json:"code"`
}

type APIHandler struct {
	re     *rengine.RuleEngine
	index  *index.FileSizeIndex
	jail   jail.Jail
	logger *slog.Logger
}

func New(opts ...func(*APIHandler)) *APIHandler {
	s := &APIHandler{
		logger: slog.New(slog.DiscardHandler),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *APIHandler) RegisterRoutes(r *gin.Engine, g *gin.RouterGroup) {
	r.NoRoute(handleNoRoute)
	// v1
	v1 := g.Group("/v1")
	v1.GET("/ping", handlePing)
	v1.GET("/records", s.handleGETBanRecords)
	v1.POST("/records", s.handlePOSTBanRecord)
	v1.DELETE("/records", s.handleDELETEBanRecord)
	v1.GET("/rules", s.handleGETBanRules)
	v1.GET("/analyzer/stats", s.handleGETAnalyzerStats)
	v1.GET("/analyzer/cache", s.handleGETAnalyzerCache)
	v1.GET("/index/stats", s.handleGETIndexStats)
	v1.GET("/index/cache", s.handleGETIndexCache)
}

// Ban info handlers

func (s *APIHandler) handleGETBanRecords(c *gin.Context) {
	recs, err := s.jail.List(c.Request.Context())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, recs)
}

func (s *APIHandler) handlePOSTBanRecord(c *gin.Context) {
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

func (s *APIHandler) handleDELETEBanRecord(c *gin.Context) {
	addrStr := c.Query("addr")
	if addrStr == "" {
		c.JSON(http.StatusBadRequest, msgResp{
			Code: http.StatusBadRequest,
			Msg:  "addr parameter is required",
		})
		return
	}

	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, msgResp{
			Code: http.StatusBadRequest,
			Msg:  err.Error(),
		})
		return
	}

	if err := s.jail.Del(c.Request.Context(), addr); err != nil {
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

func (s *APIHandler) handleGETBanRules(c *gin.Context) {
	rules, err := s.jail.Compile(c.Request.Context())
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, rules)
}

// Analyzer handlers

func (s *APIHandler) handleGETAnalyzerStats(c *gin.Context) {
	stats := s.re.GetStats()
	c.JSON(http.StatusOK, stats)
}

func (s *APIHandler) handleGETAnalyzerCache(c *gin.Context) {
	dump := s.re.DumpCache()
	c.JSON(http.StatusOK, dump)
}

// Index handlers

func (s *APIHandler) handleGETIndexStats(c *gin.Context) {
	stats := s.index.GetStats()
	c.JSON(http.StatusOK, stats)
}

func (s *APIHandler) handleGETIndexCache(c *gin.Context) {
	dump := s.index.DumpCache()
	c.JSON(http.StatusOK, dump)
}

// Misc

func handlePing(c *gin.Context) {
	c.JSON(http.StatusOK, msgResp{
		Code: http.StatusOK,
		Msg:  "pong",
	})
}

func handleNoRoute(c *gin.Context) {
	c.JSON(http.StatusNotFound, msgResp{
		Code: http.StatusNotFound,
		Msg:  "not found",
	})
}

// Options
func WithRuleEngine(re *rengine.RuleEngine) func(*APIHandler) {
	return func(s *APIHandler) {
		s.re = re
	}
}

func WithIndex(i *index.FileSizeIndex) func(*APIHandler) {
	return func(s *APIHandler) {
		s.index = i
	}
}

func WithJail(j jail.Jail) func(*APIHandler) {
	return func(s *APIHandler) {
		s.jail = j
	}
}

func WithLogger(l *slog.Logger) func(*APIHandler) {
	return func(s *APIHandler) {
		s.logger = l
	}
}
