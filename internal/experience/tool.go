package experience

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

// RegisterTools 注册全局经验库 MCP 工具。
func RegisterTools(mcpServer *mcp.Server, svc *Service, db *database.DB, logger *zap.Logger) {
	if mcpServer == nil || svc == nil {
		return
	}

	recordTool := mcp.Tool{
		Name: builtin.ToolRecordExperience,
		Description: "写入或更新全局渗透经验（跨项目、泛化后的漏洞模式/利用方式，供未来漏扫与渗透参考）。" +
			"禁止写入具体 URL、IP、凭据；须泛化为框架/CMS/服务特征与可复用检测/利用模式。" +
			"与项目黑板（upsert_project_fact）和漏洞库（record_vulnerability）分离：本项目级细节用前者，可交付 finding 用后者，可复用模式用本工具。" +
			"写入后自动向量索引；confidence=tentative 表示待更多目标验证，confirmed 表示多次验证有效。",
		ShortDescription: "写入/更新全局渗透经验",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "可选：更新已有经验 ID",
				},
				"title": map[string]interface{}{
					"type":        "string",
					"description": "经验标题（泛化，不含具体域名）",
				},
				"vuln_type": map[string]interface{}{
					"type":        "string",
					"description": "漏洞类型，如 SQL注入、RCE、文件上传",
				},
				"target_class": map[string]interface{}{
					"type":        "string",
					"description": "目标类别/技术栈，如 ThinkPHP、Spring、宝塔面板",
				},
				"fingerprint": map[string]interface{}{
					"type":        "string",
					"description": "特征指纹：响应特征、版本标识、错误信息等（不含具体 URL）",
				},
				"exploit_pattern": map[string]interface{}{
					"type":        "string",
					"description": "利用模式/步骤模板（参数化，不含真实目标地址）",
				},
				"detection_hints": map[string]interface{}{
					"type":        "string",
					"description": "检测线索：如何识别可能存在该问题",
				},
				"tags": map[string]interface{}{
					"type":        "string",
					"description": "逗号分隔标签",
				},
				"confidence": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"confirmed", "tentative", "deprecated"},
					"description": "置信度，默认 tentative",
				},
				"source_vulnerability_id": map[string]interface{}{
					"type":        "string",
					"description": "可选：来源漏洞 record_vulnerability 的 id",
				},
			},
			"required": []string{"title"},
		},
	}
	mcpServer.RegisterTool(recordTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		in := upsertInputFromArgs(args)
		if convID := conversationIDFromCtx(ctx); convID != "" {
			in.SourceConversationID = convID
		}
		if db != nil {
			if pid, err := db.GetConversationProjectID(conversationIDFromCtx(ctx)); err == nil {
				in.SourceProjectID = strings.TrimSpace(pid)
			}
		}
		exp, err := svc.Record(ctx, in)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		msg := fmt.Sprintf("全局经验已保存并索引。\nid: %s\nconfidence: %s\n\n"+
			"检索时使用 search_experience；当前目标事实仍以项目黑板为准。",
			exp.ID, exp.Confidence)
		return textResult(msg, false), nil
	})

	searchTool := mcp.Tool{
		Name: builtin.ToolSearchExperience,
		Description: "语义检索全局渗透经验库（向量相似度 + 可选 vuln_type/target_class 过滤）。" +
			"在开始验证某类漏洞或遇到相似技术栈前可调用；返回结果为**历史参考**，须在当次目标上重新验证，不可直接当作已确认漏洞。",
		ShortDescription: "检索全局渗透经验",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "检索描述，如「ThinkPHP 5.x RCE 特征」",
				},
				"vuln_type": map[string]interface{}{
					"type":        "string",
					"description": "可选：按漏洞类型过滤",
				},
				"target_class": map[string]interface{}{
					"type":        "string",
					"description": "可选：按目标类别过滤",
				},
				"top_k": map[string]interface{}{
					"type":        "integer",
					"description": "返回条数，默认 5",
				},
				"threshold": map[string]interface{}{
					"type":        "number",
					"description": "相似度阈值 0-1，默认配置值",
				},
			},
			"required": []string{"query"},
		},
	}
	mcpServer.RegisterTool(searchTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		q := strings.TrimSpace(strArg(args, "query"))
		if q == "" {
			return textResult("错误: query 必填", true), nil
		}
		req := &SearchRequest{
			Query:       q,
			VulnType:    strArg(args, "vuln_type"),
			TargetClass: strArg(args, "target_class"),
			TopK:        intArg(args, "top_k", 0),
			Threshold:   floatArg(args, "threshold", 0),
		}
		results, err := svc.Search(ctx, req)
		if err != nil {
			return textResult("检索失败: "+err.Error(), true), nil
		}
		if len(results) == 0 {
			return textResult(fmt.Sprintf("未找到与「%s」相关的全局经验。可尝试换关键词或去掉过滤条件。", q), false), nil
		}
		sort.Slice(results, func(i, j int) bool {
			return results[i].Similarity > results[j].Similarity
		})
		var b strings.Builder
		b.WriteString(fmt.Sprintf("找到 %d 条相关全局经验（历史参考，非当前目标已验证事实）：\n\n", len(results)))
		for i, r := range results {
			b.WriteString(fmt.Sprintf("--- 结果 %d (相似度: %.1f%%) ---\n", i+1, r.Similarity*100))
			b.WriteString(FormatSearchSummary(r.Experience, r.Similarity) + "\n")
			if preview := experiencePreview(r.Experience); preview != "" {
				b.WriteString("摘要: " + preview + "\n")
			}
			b.WriteString("详情请 get_experience(id)\n\n")
		}
		b.WriteString("⚠️ 以上为跨项目历史经验，仅供检测思路参考；在当前目标上须独立验证后再 record_vulnerability。\n")
		return textResult(b.String(), false), nil
	})

	getTool := mcp.Tool{
		Name:             builtin.ToolGetExperience,
		Description:      "按 ID 获取全局渗透经验完整详情。",
		ShortDescription: "获取全局经验详情",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string", "description": "经验 ID"},
			},
			"required": []string{"id"},
		},
	}
	mcpServer.RegisterTool(getTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		id := strings.TrimSpace(strArg(args, "id"))
		if id == "" {
			return textResult("错误: id 必填", true), nil
		}
		exp, err := svc.Get(id)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return textResult(FormatDetail(exp), false), nil
	})

	listTool := mcp.Tool{
		Name:             builtin.ToolListExperiences,
		Description:      "列出全局渗透经验（关键词过滤，非向量检索）。",
		ShortDescription: "列出全局经验",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"vuln_type":    map[string]interface{}{"type": "string"},
				"target_class": map[string]interface{}{"type": "string"},
				"confidence":   map[string]interface{}{"type": "string"},
				"query":        map[string]interface{}{"type": "string", "description": "关键词搜索"},
				"limit":        map[string]interface{}{"type": "integer"},
				"offset":       map[string]interface{}{"type": "integer"},
			},
		},
	}
	mcpServer.RegisterTool(listTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		filter := experienceListFilterFromArgs(args)
		list, err := svc.List(filter, intArg(args, "limit", 30), intArg(args, "offset", 0))
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("共 %d 条:\n", len(list)))
		for _, e := range list {
			b.WriteString(FormatSearchSummary(e, 0) + "\n")
		}
		return textResult(b.String(), false), nil
	})

	if logger != nil {
		logger.Debug("全局经验库 MCP 工具已注册")
	}
}

func experiencePreview(exp *database.OperationalExperience) string {
	if exp == nil {
		return ""
	}
	for _, s := range []string{exp.DetectionHints, exp.Fingerprint, exp.ExploitPattern} {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		r := []rune(s)
		if len(r) > 120 {
			return string(r[:120]) + "…"
		}
		return s
	}
	return ""
}

func upsertInputFromArgs(args map[string]interface{}) *UpsertInput {
	return &UpsertInput{
		ID:                    strArg(args, "id"),
		Title:                 strArg(args, "title"),
		VulnType:              strArg(args, "vuln_type"),
		TargetClass:           strArg(args, "target_class"),
		Fingerprint:           strArg(args, "fingerprint"),
		ExploitPattern:        strArg(args, "exploit_pattern"),
		DetectionHints:        strArg(args, "detection_hints"),
		Tags:                  strArg(args, "tags"),
		Confidence:            strArg(args, "confidence"),
		SourceVulnerabilityID: strArg(args, "source_vulnerability_id"),
	}
}

func experienceListFilterFromArgs(args map[string]interface{}) database.ExperienceListFilter {
	conf := strArg(args, "confidence")
	return database.ExperienceListFilter{
		Search:            strArg(args, "query"),
		VulnType:          strArg(args, "vuln_type"),
		TargetClass:       strArg(args, "target_class"),
		Confidence:        conf,
		ExcludeDeprecated: conf == "",
	}
}

func conversationIDFromCtx(ctx context.Context) string {
	if id := agent.ConversationIDFromContext(ctx); id != "" {
		return id
	}
	return mcp.MCPConversationIDFromContext(ctx)
}

func textResult(msg string, isErr bool) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.Content{{Type: "text", Text: msg}},
		IsError: isErr,
	}
}

func strArg(args map[string]interface{}, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func intArg(args map[string]interface{}, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return def
	}
}

func floatArg(args map[string]interface{}, key string, def float64) float64 {
	switch v := args[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	default:
		return def
	}
}
