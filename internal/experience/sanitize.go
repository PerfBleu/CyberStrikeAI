package experience

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	reHTTPURL     = regexp.MustCompile(`(?i)https?://[^\s]+`)
	rePrivateIPv4 = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	reEmail       = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
)

// SanitizeError 脱敏校验失败时的错误。
type SanitizeError struct {
	Reason string
}

func (e *SanitizeError) Error() string {
	return e.Reason
}

// ValidateGeneralizedContent 检查经验文本是否含明显 target-specific 敏感信息。
func ValidateGeneralizedContent(parts ...string) error {
	combined := strings.Join(parts, "\n")
	combined = strings.TrimSpace(combined)
	if combined == "" {
		return &SanitizeError{Reason: "经验内容不能为空"}
	}

	if m := reHTTPURL.FindString(combined); m != "" {
		return &SanitizeError{Reason: fmt.Sprintf("经验内容不得包含 URL（发现: %s）；请泛化为路径模式或技术特征", truncateForErr(m, 60))}
	}
	if m := rePrivateIPv4.FindString(combined); m != "" {
		return &SanitizeError{Reason: fmt.Sprintf("经验内容不得包含内网 IP（发现: %s）", m)}
	}
	if m := reEmail.FindString(combined); m != "" {
		return &SanitizeError{Reason: fmt.Sprintf("经验内容不得包含邮箱（发现: %s）", m)}
	}
	// 公网 IP 也提示泛化（非 RFC1918）
	if ip := findPublicIP(combined); ip != "" {
		return &SanitizeError{Reason: fmt.Sprintf("经验内容不得包含具体 IP（发现: %s）；请改用服务/框架特征描述", ip)}
	}
	return nil
}

func findPublicIP(s string) string {
	words := regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`).FindAllString(s, -1)
	for _, w := range words {
		ip := net.ParseIP(w)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return w
	}
	return ""
}

func truncateForErr(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// ValidateUpsertInput 校验写入字段。
func ValidateUpsertInput(in *UpsertInput) error {
	if in == nil {
		return &SanitizeError{Reason: "输入为空"}
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return &SanitizeError{Reason: "title 必填"}
	}
	conf := strings.TrimSpace(in.Confidence)
	if conf == "" {
		in.Confidence = "tentative"
	} else if conf != "confirmed" && conf != "tentative" && conf != "deprecated" {
		return &SanitizeError{Reason: "confidence 仅支持 confirmed | tentative | deprecated"}
	}
	if strings.TrimSpace(in.ExploitPattern) == "" && strings.TrimSpace(in.Fingerprint) == "" {
		return &SanitizeError{Reason: "fingerprint 与 exploit_pattern 至少填一项"}
	}
	return ValidateGeneralizedContent(
		title,
		in.VulnType,
		in.TargetClass,
		in.Fingerprint,
		in.ExploitPattern,
		in.DetectionHints,
		in.Tags,
	)
}
