package handler

import (
	"context"
	"strings"

	"cyberstrike-ai/internal/experience"
	"cyberstrike-ai/internal/project"
	"go.uber.org/zap"
)

// agentSessionContextBlock 注入会话工作目录、项目黑板与相关渗透经验（用于 system prompt 追加块）。
// userQuery 为当前轮用户消息，用于无感语义检索经验；可为空。
func (h *AgentHandler) agentSessionContextBlock(conversationID, userQuery string) string {
	var parts []string
	if ws := h.buildWorkspaceBlock(conversationID); ws != "" {
		parts = append(parts, ws)
	}
	if bb := h.projectBlackboardBlock(conversationID); bb != "" {
		parts = append(parts, bb)
	}
	if exp := h.experienceContextBlock(userQuery); exp != "" {
		parts = append(parts, exp)
	}
	return strings.Join(parts, "\n\n")
}

func (h *AgentHandler) buildWorkspaceBlock(conversationID string) string {
	if h == nil || h.config == nil {
		return ""
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	projectID := h.conversationProjectID(conversationID)
	rel := project.WorkspaceRootDir(h.config.Agent.WorkspaceRootDir, projectID, conversationID)
	abs, err := project.EnsureWorkspace(rel)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("创建会话工作目录失败",
				zap.String("conversationId", conversationID),
				zap.String("projectId", projectID),
				zap.String("path", rel),
				zap.Error(err))
		}
		return ""
	}
	return project.BuildWorkspaceBlock(abs)
}

// projectBlackboardBlock 根据对话 ID 构建项目事实索引块（用于注入 system prompt）。
func (h *AgentHandler) projectBlackboardBlock(conversationID string) string {
	if h == nil || h.db == nil || h.config == nil {
		return ""
	}
	if !h.config.Project.Enabled {
		return ""
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	projectID, err := h.db.GetConversationProjectID(conversationID)
	if err != nil || projectID == "" {
		return ""
	}
	block, err := project.BuildProjectBlackboardBlock(h.db, projectID, h.config.Project)
	if err != nil {
		h.logger.Warn("构建项目黑板索引失败", zap.String("conversationId", conversationID), zap.Error(err))
		return ""
	}
	return strings.TrimSpace(block)
}

func (h *AgentHandler) experienceContextBlock(userQuery string) string {
	if h == nil || h.config == nil || !h.config.Experience.AutoInjectEffective() || h.experienceProvider == nil {
		return ""
	}
	ctx := context.Background()
	svc, err := h.experienceProvider.Get(ctx)
	if err != nil {
		if h.logger != nil {
			h.logger.Debug("经验自动检索跳过", zap.Error(err))
		}
		return ""
	}
	block := experience.BuildInjectBlock(ctx, svc, &h.config.Experience, userQuery)
	return strings.TrimSpace(block)
}

// conversationProjectID 返回对话绑定的项目 ID；未绑定或查询失败时返回空字符串。
func (h *AgentHandler) conversationProjectID(conversationID string) string {
	if h == nil || h.db == nil {
		return ""
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	projectID, err := h.db.GetConversationProjectID(conversationID)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(projectID)
}
