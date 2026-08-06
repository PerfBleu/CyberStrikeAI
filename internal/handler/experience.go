package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/experience"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ExperienceHandler 全局渗透经验库 HTTP API。
type ExperienceHandler struct {
	db     *database.DB
	cfg    func() *config.Config
	logger *zap.Logger
}

// NewExperienceHandler 创建经验库处理器；cfg 应返回当前内存配置（ApplyConfig 后会更新）。
func NewExperienceHandler(db *database.DB, cfg func() *config.Config, logger *zap.Logger) *ExperienceHandler {
	return &ExperienceHandler{db: db, cfg: cfg, logger: logger}
}

func (h *ExperienceHandler) service(ctx context.Context) (*experience.Service, error) {
	if h.cfg == nil || h.cfg().Experience.Enabled == false {
		return nil, errExperienceDisabled
	}
	return experience.NewService(ctx, h.db, h.cfg(), h.logger)
}

var errExperienceDisabled = &experienceDisabledError{}

type experienceDisabledError struct{}

func (e *experienceDisabledError) Error() string {
	return "全局经验库未启用，请在系统设置中开启 experience.enabled"
}

func (h *ExperienceHandler) writeDisabled(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": errExperienceDisabled.Error(), "enabled": false})
}

// GetStats GET /api/experiences/stats
func (h *ExperienceHandler) GetStats(c *gin.Context) {
	if h.cfg == nil || !h.cfg().Experience.Enabled {
		h.writeDisabled(c)
		return
	}
	stats, err := h.db.GetExperienceStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// ListExperiences GET /api/experiences
func (h *ExperienceHandler) ListExperiences(c *gin.Context) {
	if h.cfg == nil || !h.cfg().Experience.Enabled {
		h.writeDisabled(c)
		return
	}
	filter := parseExperienceListFilter(c)
	limit, offset := parseLimitOffset(c, 50, 0)
	list, err := h.db.ListOperationalExperiences(limit, offset, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	total, _ := h.db.CountOperationalExperiences(filter)
	c.JSON(http.StatusOK, gin.H{"experiences": list, "total": total, "limit": limit, "offset": offset})
}

// GetExperience GET /api/experiences/:id
func (h *ExperienceHandler) GetExperience(c *gin.Context) {
	if h.cfg == nil || !h.cfg().Experience.Enabled {
		h.writeDisabled(c)
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	exp, err := h.db.GetOperationalExperience(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, exp)
}

type experienceWriteRequest struct {
	Title                 string `json:"title"`
	VulnType              string `json:"vuln_type"`
	TargetClass           string `json:"target_class"`
	Fingerprint           string `json:"fingerprint"`
	ExploitPattern        string `json:"exploit_pattern"`
	DetectionHints        string `json:"detection_hints"`
	Tags                  string `json:"tags"`
	Confidence            string `json:"confidence"`
	SourceVulnerabilityID string `json:"source_vulnerability_id"`
}

func (r *experienceWriteRequest) toUpsert(id string) *experience.UpsertInput {
	return &experience.UpsertInput{
		ID:                    id,
		Title:                 r.Title,
		VulnType:              r.VulnType,
		TargetClass:           r.TargetClass,
		Fingerprint:           r.Fingerprint,
		ExploitPattern:        r.ExploitPattern,
		DetectionHints:        r.DetectionHints,
		Tags:                  r.Tags,
		Confidence:            r.Confidence,
		SourceVulnerabilityID: r.SourceVulnerabilityID,
	}
}

// CreateExperience POST /api/experiences
func (h *ExperienceHandler) CreateExperience(c *gin.Context) {
	svc, err := h.service(c.Request.Context())
	if err != nil {
		h.writeDisabled(c)
		return
	}
	var req experienceWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体无效"})
		return
	}
	exp, err := svc.Record(c.Request.Context(), req.toUpsert(""))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, exp)
}

// UpdateExperience PUT /api/experiences/:id
func (h *ExperienceHandler) UpdateExperience(c *gin.Context) {
	svc, err := h.service(c.Request.Context())
	if err != nil {
		h.writeDisabled(c)
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	var req experienceWriteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体无效"})
		return
	}
	exp, err := svc.Record(c.Request.Context(), req.toUpsert(id))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, exp)
}

// DeleteExperience DELETE /api/experiences/:id
func (h *ExperienceHandler) DeleteExperience(c *gin.Context) {
	if h.cfg == nil || !h.cfg().Experience.Enabled {
		h.writeDisabled(c)
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if err := h.db.DeleteOperationalExperience(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}

type experienceSearchRequest struct {
	Query       string  `json:"query"`
	VulnType    string  `json:"vuln_type"`
	TargetClass string  `json:"target_class"`
	TopK        int     `json:"top_k"`
	Threshold   float64 `json:"threshold"`
}

// SearchExperiences POST /api/experiences/search
func (h *ExperienceHandler) SearchExperiences(c *gin.Context) {
	svc, err := h.service(c.Request.Context())
	if err != nil {
		h.writeDisabled(c)
		return
	}
	var req experienceSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体无效"})
		return
	}
	results, err := svc.Search(c.Request.Context(), &experience.SearchRequest{
		Query:       req.Query,
		VulnType:    req.VulnType,
		TargetClass: req.TargetClass,
		TopK:        req.TopK,
		Threshold:   req.Threshold,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "count": len(results)})
}

// ReindexExperience POST /api/experiences/:id/reindex
func (h *ExperienceHandler) ReindexExperience(c *gin.Context) {
	svc, err := h.service(c.Request.Context())
	if err != nil {
		h.writeDisabled(c)
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if err := svc.Reindex(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"reindexed": id})
}

// ReindexAllExperiences POST /api/experiences/reindex
func (h *ExperienceHandler) ReindexAllExperiences(c *gin.Context) {
	svc, err := h.service(c.Request.Context())
	if err != nil {
		h.writeDisabled(c)
		return
	}
	indexed, failed, err := svc.ReindexAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"indexed": indexed, "failed": failed})
}

func parseExperienceListFilter(c *gin.Context) database.ExperienceListFilter {
	conf := strings.TrimSpace(c.Query("confidence"))
	return database.ExperienceListFilter{
		Search:            strings.TrimSpace(c.Query("q")),
		VulnType:          strings.TrimSpace(c.Query("vuln_type")),
		TargetClass:       strings.TrimSpace(c.Query("target_class")),
		Confidence:        conf,
		ExcludeDeprecated: conf == "" && c.Query("include_deprecated") != "true",
	}
}

func parseLimitOffset(c *gin.Context, defLimit, defOffset int) (int, int) {
	limit := defLimit
	offset := defOffset
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		limit = v
		if limit > 200 {
			limit = 200
		}
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		offset = v
	}
	return limit, offset
}
