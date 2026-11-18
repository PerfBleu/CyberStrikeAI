package handler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAttachmentPathAllowsResolvedUploadAndWorkspace(t *testing.T) {
	root := t.TempDir()
	uploads := filepath.Join(root, "uploads")
	if err := os.MkdirAll(filepath.Join(uploads, "2026-11-11", "sess"), 0o755); err != nil {
		t.Fatal(err)
	}
	upload := filepath.Join(uploads, "2026-11-11", "sess", "流量分析_055646_124dfa.pcap")
	if err := os.WriteFile(upload, []byte("pcap"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("no"), 0o644); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	workspace := filepath.Join(work, "tmp", "workspace", "conversations", "sess")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(workspace, "note.txt")
	if err := os.WriteFile(note, []byte("note"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(uploads, filepath.Join(work, "chat_uploads")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)

	if _, err := validateChatAttachmentServerPath(upload); err != nil {
		t.Fatalf("resolved upload path: %v", err)
	}
	linked := filepath.Join(work, "chat_uploads", "2026-11-11", "sess", "流量分析_055646_124dfa.pcap")
	if _, err := validateChatAttachmentServerPath(linked); err != nil {
		t.Fatalf("symlink upload path: %v", err)
	}
	if _, err := validateChatAttachmentServerPath(note); err != nil {
		t.Fatalf("workspace path: %v", err)
	}
	if _, err := validateChatAttachmentServerPath(outside); err == nil {
		t.Fatal("path outside chat_uploads and workspace was accepted")
	}
}
