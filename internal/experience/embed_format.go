package experience

import (
	"fmt"
	"strings"
)

// FormatEmbeddingInput 与索引/query 对齐的嵌入文本格式。
func FormatEmbeddingInput(vulnType, targetClass, title, body string) string {
	vt := strings.TrimSpace(vulnType)
	tc := strings.TrimSpace(targetClass)
	t := strings.TrimSpace(title)
	b := strings.TrimSpace(body)
	return fmt.Sprintf("[漏洞类型：%s] [目标类别：%s] [标题：%s]\n%s", vt, tc, t, b)
}

// FormatQueryEmbeddingText 查询侧嵌入文本。
func FormatQueryEmbeddingText(vulnType, targetClass, query string) string {
	q := strings.TrimSpace(query)
	vt := strings.TrimSpace(vulnType)
	tc := strings.TrimSpace(targetClass)
	if vt != "" || tc != "" {
		return FormatEmbeddingInput(vt, tc, "", q)
	}
	return q
}

// BuildIndexableText 合并经验字段为可索引正文。
func BuildIndexableText(exp *UpsertInput) string {
	if exp == nil {
		return ""
	}
	var parts []string
	if s := strings.TrimSpace(exp.Fingerprint); s != "" {
		parts = append(parts, "【特征指纹】\n"+s)
	}
	if s := strings.TrimSpace(exp.DetectionHints); s != "" {
		parts = append(parts, "【检测线索】\n"+s)
	}
	if s := strings.TrimSpace(exp.ExploitPattern); s != "" {
		parts = append(parts, "【利用模式】\n"+s)
	}
	if s := strings.TrimSpace(exp.Tags); s != "" {
		parts = append(parts, "【标签】"+s)
	}
	return strings.Join(parts, "\n\n")
}

// BuildIndexableTextFromRecord 从 DB 记录构建索引文本。
func BuildIndexableTextFromRecord(title, vulnType, targetClass, fingerprint, detectionHints, exploitPattern, tags string) string {
	return BuildIndexableText(&UpsertInput{
		Title:          title,
		VulnType:       vulnType,
		TargetClass:    targetClass,
		Fingerprint:    fingerprint,
		DetectionHints: detectionHints,
		ExploitPattern: exploitPattern,
		Tags:           tags,
	})
}
