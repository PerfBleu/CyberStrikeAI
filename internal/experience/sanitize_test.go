package experience

import (
	"strings"
	"testing"
)

func TestValidateGeneralizedContent_rejectsURL(t *testing.T) {
	err := ValidateGeneralizedContent("ThinkPHP RCE", "https://example.com/admin")
	if err == nil {
		t.Fatal("expected error for URL")
	}
}

func TestValidateGeneralizedContent_rejectsPrivateIP(t *testing.T) {
	err := ValidateGeneralizedContent("内网服务", "10.0.0.1")
	if err == nil {
		t.Fatal("expected error for private IP")
	}
}

func TestValidateGeneralizedContent_acceptsGeneralized(t *testing.T) {
	err := ValidateGeneralizedContent(
		"ThinkPHP 5.0.x RCE",
		"目标类别: ThinkPHP",
		"响应含 ThinkPHP 版本标识",
		"利用: POST /index.php?s=captcha 参数 invokefunction",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFormatEmbeddingInput(t *testing.T) {
	got := FormatEmbeddingInput("RCE", "ThinkPHP", "标题", "body")
	if !strings.Contains(got, "ThinkPHP") || !strings.Contains(got, "body") {
		t.Fatalf("unexpected format: %q", got)
	}
}

func TestBuildIndexableText(t *testing.T) {
	body := BuildIndexableText(&UpsertInput{
		Fingerprint:    "fp",
		ExploitPattern: "exploit",
	})
	if !strings.Contains(body, "fp") || !strings.Contains(body, "exploit") {
		t.Fatalf("missing parts: %q", body)
	}
}
