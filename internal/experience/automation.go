package experience

import (
	"context"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

const autoInjectMinQueryRunes = 6

// GeneralizeText 将 target-specific 信息替换为占位符，便于写入全局经验库。
func GeneralizeText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = reHTTPURL.ReplaceAllString(s, "[URL]")
	s = rePrivateIPv4.ReplaceAllString(s, "[IP]")
	s = reEmail.ReplaceAllString(s, "[EMAIL]")
	// 剩余公网 IP
	for {
		ip := findPublicIP(s)
		if ip == "" {
			break
		}
		s = strings.Replace(s, ip, "[IP]", 1)
	}
	return strings.TrimSpace(s)
}

// BuildUpsertFromVulnerability 从漏洞记录构建泛化经验输入。
func BuildUpsertFromVulnerability(v *database.Vulnerability) (*UpsertInput, error) {
	if v == nil {
		return nil, fmt.Errorf("vulnerability 为空")
	}
	title := GeneralizeText(v.Title)
	if title == "" {
		title = GeneralizeText(v.Type)
	}
	if title == "" {
		title = "已验证漏洞模式"
	}

	exploitParts := []string{}
	if s := GeneralizeText(v.ReproSteps); s != "" {
		exploitParts = append(exploitParts, "【复现步骤】\n"+s)
	}
	if s := GeneralizeText(v.Evidence); s != "" {
		exploitParts = append(exploitParts, "【证据要点】\n"+s)
	}
	exploitPattern := strings.Join(exploitParts, "\n\n")

	fingerprint := GeneralizeText(v.Description)
	if fingerprint == "" {
		fingerprint = GeneralizeText(v.Target)
	}

	detectionHints := GeneralizeText(v.Preconditions)
	if detectionHints == "" {
		detectionHints = GeneralizeText(v.Description)
	}

	in := &UpsertInput{
		Title:                 title,
		VulnType:              GeneralizeText(v.Type),
		TargetClass:           inferTargetClass(v),
		Fingerprint:           fingerprint,
		ExploitPattern:        exploitPattern,
		DetectionHints:        detectionHints,
		Tags:                  strings.TrimSpace(v.Severity),
		Confidence:            "tentative",
		SourceProjectID:       strings.TrimSpace(v.ProjectID),
		SourceVulnerabilityID: strings.TrimSpace(v.ID),
		SourceConversationID:  strings.TrimSpace(v.ConversationID),
	}
	if err := ValidateUpsertInput(in); err != nil {
		return nil, err
	}
	return in, nil
}

func inferTargetClass(v *database.Vulnerability) string {
	if v == nil {
		return ""
	}
	corpus := strings.ToLower(v.Type + " " + v.Description + " " + v.Target + " " + v.Title)
	keywords := []struct {
		sub  string
		class string
	}{
		{"thinkphp", "ThinkPHP"},
		{"spring", "Spring"},
		{"struts", "Struts"},
		{"tomcat", "Tomcat"},
		{"nginx", "Nginx"},
		{"apache", "Apache"},
		{"wordpress", "WordPress"},
		{"docker", "Docker"},
		{"kubernetes", "Kubernetes"},
		{"宝塔", "宝塔面板"},
		{"weblogic", "WebLogic"},
		{"shiro", "Shiro"},
		{"fastjson", "Fastjson"},
		{"log4j", "Log4j"},
		{"redis", "Redis"},
		{"mysql", "MySQL"},
		{"api", "Web API"},
	}
	for _, kw := range keywords {
		if strings.Contains(corpus, kw.sub) {
			return kw.class
		}
	}
	if strings.Contains(corpus, "mobile") || strings.Contains(corpus, "android") || strings.Contains(corpus, "ios") {
		return "移动应用"
	}
	return "泛 Web"
}

// BuildInjectBlock 按用户消息语义检索经验，生成可注入 system prompt 的摘要块。
func BuildInjectBlock(ctx context.Context, svc *Service, cfg *config.ExperienceConfig, userQuery string) string {
	if svc == nil || cfg == nil || !cfg.AutoInjectEffective() {
		return ""
	}
	q := strings.TrimSpace(userQuery)
	if len([]rune(q)) < autoInjectMinQueryRunes {
		return ""
	}

	results, err := svc.Search(ctx, &SearchRequest{
		Query: q,
		TopK:  cfg.Retrieval.TopKEffective(),
	})
	if err != nil || len(results) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("## 相关渗透经验（系统自动检索，仅供参考）\n\n")
	b.WriteString("以下为与当前任务语义相近的**历史泛化经验**摘要；须在**本次目标**上独立验证，不可当作已确认事实。\n\n")
	for _, r := range results {
		if r == nil || r.Experience == nil {
			continue
		}
		b.WriteString(FormatSearchSummary(r.Experience, r.Similarity))
		b.WriteString("\n")
		preview := firstNonEmptyStr(
			r.Experience.DetectionHints,
			r.Experience.Fingerprint,
			r.Experience.ExploitPattern,
		)
		preview = truncateRunesGeneral(preview, 180)
		if preview != "" {
			b.WriteString("  要点: " + preview + "\n")
		}
	}
	b.WriteString("\n当前目标事实仍以项目黑板为准；需要完整字段时可调用 get_experience(id)。\n")
	return b.String()
}

// AutoRecordFromVulnerability 在漏洞落库后异步泛化写入经验库（best-effort，失败仅打日志）。
func AutoRecordFromVulnerability(ctx context.Context, provider *Provider, db *database.DB, vuln *database.Vulnerability, ownerUserID string, logger *zap.Logger) {
	if provider == nil || db == nil || vuln == nil || vuln.ID == "" {
		return
	}
	cfg := provider.cfgFn()
	if cfg == nil || !cfg.Experience.AutoRecordEffective() {
		return
	}

	go func() {
		bg := context.Background()
		if ctx != nil {
			if dl, ok := ctx.Deadline(); ok {
				var cancel context.CancelFunc
				bg, cancel = context.WithDeadline(context.Background(), dl)
				defer cancel()
			}
		}

		if existing, err := db.GetOperationalExperienceBySourceVulnerabilityID(vuln.ID); err == nil && existing != nil {
			return
		}

		in, err := BuildUpsertFromVulnerability(vuln)
		if err != nil {
			if logger != nil {
				logger.Debug("自动经验写入跳过（泛化校验未通过）",
					zap.String("vulnerability_id", vuln.ID),
					zap.Error(err))
			}
			return
		}
		if ownerUserID != "" {
			in.OwnerUserID = ownerUserID
		}

		svc, err := provider.Get(bg)
		if err != nil {
			if logger != nil {
				logger.Warn("自动经验写入失败：服务不可用", zap.Error(err))
			}
			return
		}
		exp, err := svc.Record(bg, in)
		if err != nil {
			if logger != nil {
				logger.Warn("自动经验写入失败",
					zap.String("vulnerability_id", vuln.ID),
					zap.Error(err))
			}
			return
		}
		if logger != nil {
			logger.Info("已自动写入渗透经验",
				zap.String("experience_id", exp.ID),
				zap.String("vulnerability_id", vuln.ID),
				zap.String("title", exp.Title))
		}
	}()
}

func firstNonEmptyStr(parts ...string) string {
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			return s
		}
	}
	return ""
}

func truncateRunesGeneral(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
