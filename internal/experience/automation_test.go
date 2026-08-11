package experience

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
)

func TestGeneralizeText(t *testing.T) {
	in := "访问 https://example.com/admin?id=1 与 10.0.0.5 及 admin@test.com"
	out := GeneralizeText(in)
	if strings.Contains(out, "example.com") {
		t.Fatalf("URL not generalized: %q", out)
	}
	if strings.Contains(out, "10.0.0.5") {
		t.Fatalf("IP not generalized: %q", out)
	}
	if strings.Contains(out, "admin@test.com") {
		t.Fatalf("email not generalized: %q", out)
	}
}

func TestBuildUpsertFromVulnerability(t *testing.T) {
	v := &database.Vulnerability{
		ID:             "v1",
		Title:          "登录接口 SQL 注入",
		Type:           "SQL注入",
		Description:    "id 参数未过滤",
		ReproSteps:     "1. 在 id 参数注入 payload\n2. 观察报错",
		Evidence:       "响应含 syntax error",
		Preconditions:  "无需登录",
		Severity:       "high",
		ConversationID: "c1",
	}
	in, err := BuildUpsertFromVulnerability(v)
	if err != nil {
		t.Fatal(err)
	}
	if in.Title == "" || in.ExploitPattern == "" {
		t.Fatalf("unexpected input: %+v", in)
	}
	if in.Confidence != "tentative" {
		t.Fatalf("confidence = %q", in.Confidence)
	}
}

func TestBuildUpsertFromVulnerabilityGeneralizesURL(t *testing.T) {
	v := &database.Vulnerability{
		Title:          "test",
		Type:           "RCE",
		Description:    "see https://secret.internal/poc",
		ReproSteps:     "curl http://10.0.0.1/shell",
		Evidence:       "ok",
		Impact:         "rce",
		Recommendation: "patch",
	}
	in, err := BuildUpsertFromVulnerability(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(in.ExploitPattern, "10.0.0.1") || strings.Contains(in.Fingerprint, "secret.internal") {
		t.Fatalf("expected generalized content: %+v", in)
	}
}
