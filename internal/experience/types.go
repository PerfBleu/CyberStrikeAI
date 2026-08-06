package experience

import (
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/database"
)

// SearchRequest 经验语义检索请求。
type SearchRequest struct {
	Query       string
	VulnType    string
	TargetClass string
	TopK        int
	Threshold   float64
}

// SearchResult 单条检索命中。
type SearchResult struct {
	Experience *database.OperationalExperience
	Score      float64
	Similarity float64
	ChunkText  string
}

// UpsertInput 写入/更新经验输入。
type UpsertInput struct {
	ID                    string
	Title                 string
	VulnType              string
	TargetClass           string
	Fingerprint           string
	ExploitPattern        string
	DetectionHints        string
	Tags                  string
	Confidence            string
	SourceProjectID       string
	SourceVulnerabilityID string
	SourceConversationID  string
	OwnerUserID           string
}

// FormatDetail 格式化经验详情供 MCP 返回。
func FormatDetail(exp *database.OperationalExperience) string {
	if exp == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("id: " + exp.ID + "\n")
	b.WriteString("title: " + exp.Title + "\n")
	if exp.VulnType != "" {
		b.WriteString("vuln_type: " + exp.VulnType + "\n")
	}
	if exp.TargetClass != "" {
		b.WriteString("target_class: " + exp.TargetClass + "\n")
	}
	b.WriteString("confidence: " + exp.Confidence + "\n")
	if exp.Tags != "" {
		b.WriteString("tags: " + exp.Tags + "\n")
	}
	b.WriteString("updated_at: " + exp.UpdatedAt.Format(time.RFC3339) + "\n")
	if exp.Fingerprint != "" {
		b.WriteString("\n--- fingerprint ---\n" + exp.Fingerprint + "\n")
	}
	if exp.DetectionHints != "" {
		b.WriteString("\n--- detection_hints ---\n" + exp.DetectionHints + "\n")
	}
	if exp.ExploitPattern != "" {
		b.WriteString("\n--- exploit_pattern ---\n" + exp.ExploitPattern + "\n")
	}
	b.WriteString("\n注意：以上为历史渗透经验参考，须在**当前目标**上重新验证，不可当作已确认事实。\n")
	return b.String()
}

// FormatSearchSummary 格式化列表行。
func FormatSearchSummary(exp *database.OperationalExperience, similarity float64) string {
	if exp == nil {
		return ""
	}
	line := fmt.Sprintf("- id=%s | 相似度=%.1f%% | %s | %s | %s",
		exp.ID, similarity*100, exp.Confidence, exp.VulnType, exp.Title)
	if exp.TargetClass != "" {
		line += " | class=" + exp.TargetClass
	}
	return line
}
