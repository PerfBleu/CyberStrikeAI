package security

import (
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestAttachRBACStoreBootstrapsAdminPassword(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "auth-bootstrap.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewAuthManager(12)
	generated, err := manager.AttachRBACStore(db)
	if err != nil {
		t.Fatalf("AttachRBACStore: %v", err)
	}
	if generated == "" {
		t.Fatal("expected generated admin password on first bootstrap")
	}
	if !manager.CheckUserPassword("admin", generated) {
		t.Fatal("generated password should authenticate admin")
	}

	second, err := manager.AttachRBACStore(db)
	if err != nil {
		t.Fatalf("AttachRBACStore second call: %v", err)
	}
	if second != "" {
		t.Fatalf("expected no password on second bootstrap, got %q", second)
	}
}

func TestAttachRBACStoreUsesConfiguredAdminPassword(t *testing.T) {
	t.Setenv(EnvAdminPassword, "configured-admin-pass")
	db, err := database.NewDB(filepath.Join(t.TempDir(), "auth-bootstrap-configured.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewAuthManager(12)
	got, err := manager.AttachRBACStore(db)
	if err != nil {
		t.Fatalf("AttachRBACStore: %v", err)
	}
	if got != "configured-admin-pass" {
		t.Fatalf("password = %q", got)
	}
	if !manager.CheckUserPassword("admin", "configured-admin-pass") {
		t.Fatal("configured password should authenticate admin")
	}
}

func TestInitialAdminPasswordRejectsShortValue(t *testing.T) {
	t.Setenv(EnvAdminPassword, "short")
	if _, err := initialAdminPassword(); err == nil {
		t.Fatal("expected short password to be rejected")
	}
}
