package experience

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/knowledge"

	"go.uber.org/zap"
)

// Service 全局经验库：CRUD + 向量索引与检索。
type Service struct {
	db       *database.DB
	embedder *knowledge.Embedder
	cfg      *config.ExperienceConfig
	appCfg   *config.Config
	logger   *zap.Logger
}

// NewService 创建经验库服务；需 experience.enabled 且 embedding API 可用。
func NewService(ctx context.Context, db *database.DB, appCfg *config.Config, logger *zap.Logger) (*Service, error) {
	if db == nil || appCfg == nil {
		return nil, fmt.Errorf("experience: db 或 config 为空")
	}
	if !appCfg.Experience.Enabled {
		return nil, fmt.Errorf("experience: 未启用")
	}
	kc := config.KnowledgeConfigForExperienceEmbedder(appCfg)
	embedder, err := knowledge.NewEmbedder(ctx, kc, &appCfg.OpenAI, logger)
	if err != nil {
		return nil, fmt.Errorf("experience embedder: %w", err)
	}
	expCfg := appCfg.Experience
	return &Service{
		db:       db,
		embedder: embedder,
		cfg:      &expCfg,
		appCfg:   appCfg,
		logger:   logger,
	}, nil
}

// Record 创建或更新经验并重建向量索引。
func (s *Service) Record(ctx context.Context, in *UpsertInput) (*database.OperationalExperience, error) {
	if err := ValidateUpsertInput(in); err != nil {
		return nil, err
	}

	var exp *database.OperationalExperience
	var err error
	id := strings.TrimSpace(in.ID)
	if id != "" {
		existing, getErr := s.db.GetOperationalExperience(id)
		if getErr != nil {
			return nil, getErr
		}
		existing.Title = strings.TrimSpace(in.Title)
		existing.VulnType = strings.TrimSpace(in.VulnType)
		existing.TargetClass = strings.TrimSpace(in.TargetClass)
		existing.Fingerprint = strings.TrimSpace(in.Fingerprint)
		existing.ExploitPattern = strings.TrimSpace(in.ExploitPattern)
		existing.DetectionHints = strings.TrimSpace(in.DetectionHints)
		existing.Tags = strings.TrimSpace(in.Tags)
		existing.Confidence = strings.TrimSpace(in.Confidence)
		if existing.Confidence == "" {
			existing.Confidence = "tentative"
		}
		if in.SourceProjectID != "" {
			existing.SourceProjectID = strings.TrimSpace(in.SourceProjectID)
		}
		if in.SourceVulnerabilityID != "" {
			existing.SourceVulnerabilityID = strings.TrimSpace(in.SourceVulnerabilityID)
		}
		if err := s.db.UpdateOperationalExperience(id, existing); err != nil {
			return nil, err
		}
		exp = existing
	} else {
		exp = &database.OperationalExperience{
			Title:                 strings.TrimSpace(in.Title),
			VulnType:              strings.TrimSpace(in.VulnType),
			TargetClass:           strings.TrimSpace(in.TargetClass),
			Fingerprint:           strings.TrimSpace(in.Fingerprint),
			ExploitPattern:        strings.TrimSpace(in.ExploitPattern),
			DetectionHints:        strings.TrimSpace(in.DetectionHints),
			Tags:                  strings.TrimSpace(in.Tags),
			Confidence:            strings.TrimSpace(in.Confidence),
			SourceProjectID:       strings.TrimSpace(in.SourceProjectID),
			SourceVulnerabilityID: strings.TrimSpace(in.SourceVulnerabilityID),
			SourceConversationID:  strings.TrimSpace(in.SourceConversationID),
			OwnerUserID:           strings.TrimSpace(in.OwnerUserID),
		}
		if exp.Confidence == "" {
			exp.Confidence = "tentative"
		}
		exp, err = s.db.CreateOperationalExperience(exp)
		if err != nil {
			return nil, err
		}
	}

	if err := s.reindexExperience(ctx, exp); err != nil {
		return exp, fmt.Errorf("经验已保存但向量索引失败: %w", err)
	}
	return exp, nil
}

func (s *Service) reindexExperience(ctx context.Context, exp *database.OperationalExperience) error {
	if exp == nil {
		return fmt.Errorf("experience 为空")
	}
	body := BuildIndexableTextFromRecord(
		exp.Title, exp.VulnType, exp.TargetClass,
		exp.Fingerprint, exp.DetectionHints, exp.ExploitPattern, exp.Tags,
	)
	embedText := FormatEmbeddingInput(exp.VulnType, exp.TargetClass, exp.Title, body)
	vec, err := s.embedder.EmbedText(ctx, embedText)
	if err != nil {
		return err
	}
	vecJSON, err := json.Marshal(vec)
	if err != nil {
		return err
	}
	model := s.embedder.EmbeddingModelName()
	if err := s.db.DeleteExperienceEmbeddings(exp.ID); err != nil {
		return err
	}
	return s.db.InsertExperienceEmbedding(&database.ExperienceEmbedding{
		ExperienceID:   exp.ID,
		ChunkIndex:     0,
		ChunkText:      body,
		EmbeddingJSON:  string(vecJSON),
		EmbeddingModel: model,
		EmbeddingDim:   len(vec),
	})
}

// Get 按 ID 获取经验。
func (s *Service) Get(id string) (*database.OperationalExperience, error) {
	return s.db.GetOperationalExperience(id)
}

// Search 向量语义检索（含结构化预过滤）。
func (s *Service) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	if req == nil {
		return nil, fmt.Errorf("请求不能为空")
	}
	q := strings.TrimSpace(req.Query)
	if q == "" {
		return nil, fmt.Errorf("query 不能为空")
	}

	topK := req.TopK
	if topK <= 0 && s.cfg != nil {
		topK = s.cfg.Retrieval.TopKEffective()
	}
	if topK <= 0 {
		topK = 5
	}
	threshold := req.Threshold
	if threshold <= 0 && s.cfg != nil {
		threshold = s.cfg.Retrieval.SimilarityThresholdEffective()
	}
	if threshold <= 0 {
		threshold = 0.65
	}

	filter := database.ExperienceListFilter{
		VulnType:          strings.TrimSpace(req.VulnType),
		TargetClass:       strings.TrimSpace(req.TargetClass),
		ExcludeDeprecated: true,
	}
	rows, err := s.db.ListExperienceEmbeddingsForSearch(filter)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	queryText := FormatQueryEmbeddingText(req.VulnType, req.TargetClass, q)
	queryVec, err := s.embedder.EmbedText(ctx, queryText)
	if err != nil {
		return nil, fmt.Errorf("向量化查询失败: %w", err)
	}
	expectedModel := s.embedder.EmbeddingModelName()
	queryDim := len(queryVec)

	type candidate struct {
		emb        *database.ExperienceEmbedding
		similarity float64
	}
	candidates := make([]candidate, 0, len(rows))
	for _, row := range rows {
		if row == nil {
			continue
		}
		if expectedModel != "" && strings.TrimSpace(row.EmbeddingModel) != "" &&
			strings.TrimSpace(row.EmbeddingModel) != expectedModel {
			continue
		}
		var vec []float32
		if err := json.Unmarshal([]byte(row.EmbeddingJSON), &vec); err != nil {
			if s.logger != nil {
				s.logger.Warn("解析经验向量失败", zap.String("id", row.ID), zap.Error(err))
			}
			continue
		}
		if queryDim > 0 && len(vec) != queryDim {
			continue
		}
		sim := cosineSimilarity(queryVec, vec)
		if sim >= threshold {
			candidates = append(candidates, candidate{emb: row, similarity: sim})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].similarity > candidates[j].similarity
	})
	if len(candidates) > topK {
		candidates = candidates[:topK]
	}

	out := make([]*SearchResult, 0, len(candidates))
	for _, c := range candidates {
		exp, err := s.db.GetOperationalExperience(c.emb.ExperienceID)
		if err != nil {
			continue
		}
		out = append(out, &SearchResult{
			Experience: exp,
			Score:      c.similarity,
			Similarity: c.similarity,
			ChunkText:  c.emb.ChunkText,
		})
	}
	return out, nil
}

// Reindex 重建单条经验的向量索引。
func (s *Service) Reindex(ctx context.Context, id string) error {
	exp, err := s.db.GetOperationalExperience(id)
	if err != nil {
		return err
	}
	return s.reindexExperience(ctx, exp)
}

// ReindexAll 重建全部经验向量（best-effort，跳过失败项）。
func (s *Service) ReindexAll(ctx context.Context) (indexed, failed int, err error) {
	list, err := s.db.ListOperationalExperiences(10000, 0, database.ExperienceListFilter{})
	if err != nil {
		return 0, 0, err
	}
	for _, exp := range list {
		if exp == nil {
			continue
		}
		if rerr := s.reindexExperience(ctx, exp); rerr != nil {
			failed++
			if s.logger != nil {
				s.logger.Warn("经验 reindex 失败", zap.String("id", exp.ID), zap.Error(rerr))
			}
		} else {
			indexed++
		}
	}
	return indexed, failed, nil
}

// Delete 删除经验。
func (s *Service) Delete(id string) error {
	return s.db.DeleteOperationalExperience(id)
}

func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i] * b[i])
		normA += float64(a[i] * a[i])
		normB += float64(b[i] * b[i])
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// List 关键词列表（无向量）。
func (s *Service) List(filter database.ExperienceListFilter, limit, offset int) ([]*database.OperationalExperience, error) {
	if !filter.ExcludeDeprecated && filter.Confidence == "" {
		filter.ExcludeDeprecated = true
	}
	return s.db.ListOperationalExperiences(limit, offset, filter)
}
