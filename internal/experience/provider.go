package experience

import (
	"context"
	"fmt"
	"sync"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

// Provider 缓存经验库 Service，配置变更后调用 Invalidate。
type Provider struct {
	mu     sync.Mutex
	svc    *Service
	db     *database.DB
	cfgFn  func() *config.Config
	logger *zap.Logger
}

// NewProvider 创建经验库 Provider；cfgFn 应返回当前生效配置。
func NewProvider(db *database.DB, cfgFn func() *config.Config, logger *zap.Logger) *Provider {
	return &Provider{db: db, cfgFn: cfgFn, logger: logger}
}

// Get 返回可用 Service；未启用或初始化失败时返回 error。
func (p *Provider) Get(ctx context.Context) (*Service, error) {
	if p == nil || p.db == nil || p.cfgFn == nil {
		return nil, fmt.Errorf("experience provider 未初始化")
	}
	cfg := p.cfgFn()
	if cfg == nil || !cfg.Experience.Enabled {
		return nil, fmt.Errorf("experience: 未启用")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.svc != nil {
		return p.svc, nil
	}
	svc, err := NewService(ctx, p.db, cfg, p.logger)
	if err != nil {
		return nil, err
	}
	p.svc = svc
	return svc, nil
}

// Invalidate 丢弃缓存的 Service（配置 reload 后调用）。
func (p *Provider) Invalidate() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.svc = nil
	p.mu.Unlock()
}
