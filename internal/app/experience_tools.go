package app

import (
	"context"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/experience"
	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

func registerExperienceTools(mcpServer *mcp.Server, db *database.DB, cfg *config.Config, logger *zap.Logger) {
	if mcpServer == nil || db == nil || cfg == nil || !cfg.Experience.Enabled {
		if logger != nil && cfg != nil && !cfg.Experience.Enabled {
			logger.Info("全局经验库工具未注册（未启用）")
		}
		return
	}
	svc, err := experience.NewService(context.Background(), db, cfg, logger)
	if err != nil {
		if logger != nil {
			logger.Warn("全局经验库初始化失败，工具未注册", zap.Error(err))
		}
		return
	}
	experience.RegisterTools(mcpServer, svc, db, logger)
	if logger != nil {
		logger.Info("全局经验库 MCP 工具注册成功")
	}
}
