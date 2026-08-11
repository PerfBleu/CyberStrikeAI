package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// OperationalExperience 全局渗透经验条目（泛化、跨项目）。
type OperationalExperience struct {
	ID                    string    `json:"id"`
	Title                 string    `json:"title"`
	VulnType              string    `json:"vuln_type"`
	TargetClass           string    `json:"target_class"`
	Fingerprint           string    `json:"fingerprint"`
	ExploitPattern        string    `json:"exploit_pattern"`
	DetectionHints        string    `json:"detection_hints"`
	Tags                  string    `json:"tags"`
	Confidence            string    `json:"confidence"` // confirmed | tentative | deprecated
	SourceProjectID       string    `json:"source_project_id,omitempty"`
	SourceVulnerabilityID string    `json:"source_vulnerability_id,omitempty"`
	SourceConversationID  string    `json:"source_conversation_id,omitempty"`
	OwnerUserID           string    `json:"owner_user_id,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// ExperienceListFilter 经验列表/搜索筛选。
type ExperienceListFilter struct {
	ID           string
	Search       string
	VulnType     string
	TargetClass  string
	Confidence   string
	ExcludeDeprecated bool
}

// ExperienceEmbedding 经验向量块。
type ExperienceEmbedding struct {
	ID             string
	ExperienceID   string
	ChunkIndex     int
	ChunkText      string
	EmbeddingJSON  string
	EmbeddingModel string
	EmbeddingDim   int
	CreatedAt      time.Time
}

func (f ExperienceListFilter) appendWhereAlias(alias string, query string, args []interface{}) (string, []interface{}) {
	prefix := strings.TrimSpace(alias)
	if prefix != "" {
		prefix += "."
	}
	if f.ID != "" {
		query += " AND " + prefix + "id = ?"
		args = append(args, f.ID)
	}
	if f.VulnType != "" {
		query += " AND TRIM(" + prefix + "vuln_type) = TRIM(?) COLLATE NOCASE"
		args = append(args, f.VulnType)
	}
	if f.TargetClass != "" {
		query += " AND TRIM(" + prefix + "target_class) = TRIM(?) COLLATE NOCASE"
		args = append(args, f.TargetClass)
	}
	if f.Confidence != "" {
		query += " AND " + prefix + "confidence = ?"
		args = append(args, f.Confidence)
	} else if f.ExcludeDeprecated {
		query += " AND " + prefix + "confidence != 'deprecated'"
	}
	search := strings.TrimSpace(f.Search)
	if search != "" {
		pattern := escapeVulnerabilityLikePattern(search)
		query += ` AND (
			LOWER(` + prefix + `title) LIKE LOWER(?) OR
			LOWER(COALESCE(` + prefix + `vuln_type, '')) LIKE LOWER(?) OR
			LOWER(COALESCE(` + prefix + `target_class, '')) LIKE LOWER(?) OR
			LOWER(COALESCE(` + prefix + `fingerprint, '')) LIKE LOWER(?) OR
			LOWER(COALESCE(` + prefix + `exploit_pattern, '')) LIKE LOWER(?) OR
			LOWER(COALESCE(` + prefix + `detection_hints, '')) LIKE LOWER(?) OR
			LOWER(COALESCE(` + prefix + `tags, '')) LIKE LOWER(?)
		)`
		for i := 0; i < 7; i++ {
			args = append(args, pattern)
		}
	}
	return query, args
}

func (f ExperienceListFilter) appendWhere(query string, args []interface{}) (string, []interface{}) {
	return f.appendWhereAlias("", query, args)
}

// CreateOperationalExperience 创建经验条目。
func (db *DB) CreateOperationalExperience(exp *OperationalExperience) (*OperationalExperience, error) {
	if exp.ID == "" {
		exp.ID = uuid.New().String()
	}
	if exp.Confidence == "" {
		exp.Confidence = "tentative"
	}
	now := time.Now()
	if exp.CreatedAt.IsZero() {
		exp.CreatedAt = now
	}
	exp.UpdatedAt = now

	_, err := db.Exec(`
		INSERT INTO operational_experiences (
			id, title, vuln_type, target_class, fingerprint, exploit_pattern, detection_hints, tags,
			confidence, source_project_id, source_vulnerability_id, source_conversation_id, owner_user_id,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		exp.ID, exp.Title, exp.VulnType, exp.TargetClass, exp.Fingerprint, exp.ExploitPattern,
		exp.DetectionHints, exp.Tags, exp.Confidence,
		nullIfEmpty(exp.SourceProjectID), nullIfEmpty(exp.SourceVulnerabilityID), nullIfEmpty(exp.SourceConversationID),
		nullIfEmpty(exp.OwnerUserID), exp.CreatedAt, exp.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("创建经验条目失败: %w", err)
	}
	return exp, nil
}

// GetOperationalExperience 按 ID 获取经验。
func (db *DB) GetOperationalExperience(id string) (*OperationalExperience, error) {
	var exp OperationalExperience
	err := db.QueryRow(`
		SELECT id, title, COALESCE(vuln_type,''), COALESCE(target_class,''),
		       COALESCE(fingerprint,''), COALESCE(exploit_pattern,''), COALESCE(detection_hints,''),
		       COALESCE(tags,''), confidence,
		       COALESCE(source_project_id,''), COALESCE(source_vulnerability_id,''), COALESCE(source_conversation_id,''),
		       COALESCE(owner_user_id,''), created_at, updated_at
		FROM operational_experiences WHERE id = ?`, id).Scan(
		&exp.ID, &exp.Title, &exp.VulnType, &exp.TargetClass,
		&exp.Fingerprint, &exp.ExploitPattern, &exp.DetectionHints, &exp.Tags, &exp.Confidence,
		&exp.SourceProjectID, &exp.SourceVulnerabilityID, &exp.SourceConversationID, &exp.OwnerUserID,
		&exp.CreatedAt, &exp.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("经验条目不存在")
		}
		return nil, fmt.Errorf("获取经验条目失败: %w", err)
	}
	return &exp, nil
}

// GetOperationalExperienceBySourceVulnerabilityID 按来源漏洞 ID 查是否已自动沉淀经验。
func (db *DB) GetOperationalExperienceBySourceVulnerabilityID(vulnID string) (*OperationalExperience, error) {
	vulnID = strings.TrimSpace(vulnID)
	if vulnID == "" {
		return nil, fmt.Errorf("vulnerability id 为空")
	}
	var exp OperationalExperience
	err := db.QueryRow(`
		SELECT id, title, COALESCE(vuln_type,''), COALESCE(target_class,''),
		       COALESCE(fingerprint,''), COALESCE(exploit_pattern,''), COALESCE(detection_hints,''),
		       COALESCE(tags,''), confidence,
		       COALESCE(source_project_id,''), COALESCE(source_vulnerability_id,''), COALESCE(source_conversation_id,''),
		       COALESCE(owner_user_id,''), created_at, updated_at
		FROM operational_experiences WHERE source_vulnerability_id = ? LIMIT 1`, vulnID).Scan(
		&exp.ID, &exp.Title, &exp.VulnType, &exp.TargetClass,
		&exp.Fingerprint, &exp.ExploitPattern, &exp.DetectionHints, &exp.Tags, &exp.Confidence,
		&exp.SourceProjectID, &exp.SourceVulnerabilityID, &exp.SourceConversationID, &exp.OwnerUserID,
		&exp.CreatedAt, &exp.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("按来源漏洞查询经验失败: %w", err)
	}
	return &exp, nil
}

// UpdateOperationalExperience 更新经验（不含向量，向量由 experience 包单独重建）。
func (db *DB) UpdateOperationalExperience(id string, exp *OperationalExperience) error {
	exp.UpdatedAt = time.Now()
	_, err := db.Exec(`
		UPDATE operational_experiences SET
			title = ?, vuln_type = ?, target_class = ?, fingerprint = ?, exploit_pattern = ?,
			detection_hints = ?, tags = ?, confidence = ?,
			source_project_id = ?, source_vulnerability_id = ?, updated_at = ?
		WHERE id = ?`,
		exp.Title, exp.VulnType, exp.TargetClass, exp.Fingerprint, exp.ExploitPattern,
		exp.DetectionHints, exp.Tags, exp.Confidence,
		nullIfEmpty(exp.SourceProjectID), nullIfEmpty(exp.SourceVulnerabilityID), exp.UpdatedAt, id,
	)
	if err != nil {
		return fmt.Errorf("更新经验条目失败: %w", err)
	}
	return nil
}

// ListOperationalExperiences 列出经验。
func (db *DB) ListOperationalExperiences(limit, offset int, filter ExperienceListFilter) ([]*OperationalExperience, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, title, COALESCE(vuln_type,''), COALESCE(target_class,''),
		       COALESCE(fingerprint,''), COALESCE(exploit_pattern,''), COALESCE(detection_hints,''),
		       COALESCE(tags,''), confidence,
		       COALESCE(source_project_id,''), COALESCE(source_vulnerability_id,''), COALESCE(source_conversation_id,''),
		       COALESCE(owner_user_id,''), created_at, updated_at
		FROM operational_experiences WHERE 1=1`
	args := []interface{}{}
	query, args = filter.appendWhere(query, args)
	query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询经验列表失败: %w", err)
	}
	defer rows.Close()

	var out []*OperationalExperience
	for rows.Next() {
		exp, scanErr := scanOperationalExperience(rows)
		if scanErr != nil {
			db.logger.Warn("扫描经验记录失败", zap.Error(scanErr))
			continue
		}
		out = append(out, exp)
	}
	return out, rows.Err()
}

func scanOperationalExperience(rows *sql.Rows) (*OperationalExperience, error) {
	var exp OperationalExperience
	err := rows.Scan(
		&exp.ID, &exp.Title, &exp.VulnType, &exp.TargetClass,
		&exp.Fingerprint, &exp.ExploitPattern, &exp.DetectionHints, &exp.Tags, &exp.Confidence,
		&exp.SourceProjectID, &exp.SourceVulnerabilityID, &exp.SourceConversationID, &exp.OwnerUserID,
		&exp.CreatedAt, &exp.UpdatedAt,
	)
	return &exp, err
}

// DeleteExperienceEmbeddings 删除某经验全部向量块。
func (db *DB) DeleteExperienceEmbeddings(experienceID string) error {
	_, err := db.Exec(`DELETE FROM experience_embeddings WHERE experience_id = ?`, experienceID)
	if err != nil {
		return fmt.Errorf("删除经验向量失败: %w", err)
	}
	return nil
}

// InsertExperienceEmbedding 插入单条向量块。
func (db *DB) InsertExperienceEmbedding(row *ExperienceEmbedding) error {
	if row.ID == "" {
		row.ID = uuid.New().String()
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now()
	}
	_, err := db.Exec(`
		INSERT INTO experience_embeddings (id, experience_id, chunk_index, chunk_text, embedding, embedding_model, embedding_dim, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.ExperienceID, row.ChunkIndex, row.ChunkText, row.EmbeddingJSON,
		row.EmbeddingModel, row.EmbeddingDim, row.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("插入经验向量失败: %w", err)
	}
	return nil
}

// ListExperienceEmbeddingsForSearch 返回可用于向量检索的全部 embedding 行（可按 filter 预筛 experience）。
func (db *DB) ListExperienceEmbeddingsForSearch(filter ExperienceListFilter) ([]*ExperienceEmbedding, error) {
	query := `
		SELECT e.id, e.experience_id, e.chunk_index, e.chunk_text, e.embedding, e.embedding_model, e.embedding_dim, e.created_at
		FROM experience_embeddings e
		INNER JOIN operational_experiences x ON x.id = e.experience_id
		WHERE 1=1`
	args := []interface{}{}
	query, args = filter.appendWhereAlias("x", query, args)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询经验向量失败: %w", err)
	}
	defer rows.Close()

	var embeds []*ExperienceEmbedding
	for rows.Next() {
		var emb ExperienceEmbedding
		if err := rows.Scan(
			&emb.ID, &emb.ExperienceID, &emb.ChunkIndex, &emb.ChunkText, &emb.EmbeddingJSON,
			&emb.EmbeddingModel, &emb.EmbeddingDim, &emb.CreatedAt,
		); err != nil {
			db.logger.Warn("扫描经验向量行失败", zap.Error(err))
			continue
		}
		embeds = append(embeds, &emb)
	}
	return embeds, rows.Err()
}

// DeleteOperationalExperience 删除经验条目（向量由外键 CASCADE 删除）。
func (db *DB) DeleteOperationalExperience(id string) error {
	res, err := db.Exec(`DELETE FROM operational_experiences WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除经验条目失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("经验条目不存在")
	}
	return nil
}

// CountOperationalExperiences 统计经验条数。
func (db *DB) CountOperationalExperiences(filter ExperienceListFilter) (int, error) {
	query := `SELECT COUNT(*) FROM operational_experiences WHERE 1=1`
	args := []interface{}{}
	query, args = filter.appendWhere(query, args)
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计经验失败: %w", err)
	}
	return n, nil
}

// CountExperienceEmbeddings 统计已索引向量块数量。
func (db *DB) CountExperienceEmbeddings() (int, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM experience_embeddings`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ExperienceStats 经验库统计。
type ExperienceStats struct {
	Total      int            `json:"total"`
	Indexed    int            `json:"indexed"`
	ByConfidence map[string]int `json:"by_confidence"`
}

// GetExperienceStats 聚合经验统计。
func (db *DB) GetExperienceStats() (*ExperienceStats, error) {
	out := &ExperienceStats{ByConfidence: map[string]int{}}
	if err := db.QueryRow(`SELECT COUNT(*) FROM operational_experiences`).Scan(&out.Total); err != nil {
		return nil, err
	}
	out.Indexed, _ = db.CountExperienceEmbeddings()
	rows, err := db.Query(`SELECT confidence, COUNT(*) FROM operational_experiences GROUP BY confidence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var conf string
		var c int
		if err := rows.Scan(&conf, &c); err != nil {
			continue
		}
		out.ByConfidence[conf] = c
	}
	return out, rows.Err()
}
