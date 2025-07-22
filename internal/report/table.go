package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/yourorg/unpass/internal/types"
)

// TableGenerator 表格报告生成器
type TableGenerator struct{}

func NewTableGenerator() *TableGenerator {
	return &TableGenerator{}
}

// Generate 生成包含凭据标题的表格报告
func (g *TableGenerator) Generate(writer io.Writer, report *types.AuditReport) error {
	// 报告标题
	fmt.Fprintln(writer, "Name:         unpass-security-audit")
	fmt.Fprintln(writer, "Namespace:    security")
	fmt.Fprintf(writer, "Created:      %s\n", report.Timestamp.Format("Mon, 02 Jan 2006 15:04:05 MST"))
	fmt.Fprintln(writer)
	
	// 基本统计
	fmt.Fprintln(writer, "Summary:")
	fmt.Fprintf(writer, "  Total Credentials:    %d\n", report.Summary.TotalCredentials)
	fmt.Fprintf(writer, "  Issues Found:         %d\n", report.Summary.IssuesFound)
	fmt.Fprintln(writer)
	
	// 问题统计
	if len(report.Summary.ByType) > 0 {
		fmt.Fprintln(writer, "Issues by Category:")
		
		if count, exists := report.Summary.ByType[types.DetectionMissing2FA]; exists && count > 0 {
			fmt.Fprintf(writer, "  Missing 2FA:          %d\n", count)
		}
		
		if count, exists := report.Summary.ByType[types.DetectionMissingPasskey]; exists && count > 0 {
			fmt.Fprintf(writer, "  Missing Passkey:      %d\n", count)
		}
		fmt.Fprintln(writer)
	}
	
	// 详细问题列表
	if len(report.Results) > 0 {
		// 按类型分组
		twofaResults := []types.DetectionResult{}
		passkeyResults := []types.DetectionResult{}
		
		for _, result := range report.Results {
			switch result.Type {
			case types.DetectionMissing2FA:
				twofaResults = append(twofaResults, result)
			case types.DetectionMissingPasskey:
				passkeyResults = append(passkeyResults, result)
			}
		}
		
		// 2FA问题
		if len(twofaResults) > 0 {
			fmt.Fprintln(writer, "Two-Factor Authentication Issues:")
			sort.Slice(twofaResults, func(i, j int) bool {
				domainI := g.extractDomain(twofaResults[i].Metadata)
				domainJ := g.extractDomain(twofaResults[j].Metadata)
				if domainI != domainJ {
					return domainI < domainJ
				}
				return twofaResults[i].Title < twofaResults[j].Title
			})
			
			currentDomain := ""
			for _, result := range twofaResults {
				domain := g.extractDomain(result.Metadata)
				if domain != currentDomain {
					currentDomain = domain
					fmt.Fprintf(writer, "  %s:\n", domain)
				}
				fmt.Fprintf(writer, "    - %s\n", result.Title)
			}
			fmt.Fprintln(writer)
		}
		
		// Passkey问题
		if len(passkeyResults) > 0 {
			fmt.Fprintln(writer, "Passkey Authentication Issues:")
			sort.Slice(passkeyResults, func(i, j int) bool {
				domainI := g.extractDomain(passkeyResults[i].Metadata)
				domainJ := g.extractDomain(passkeyResults[j].Metadata)
				if domainI != domainJ {
					return domainI < domainJ
				}
				return passkeyResults[i].Title < passkeyResults[j].Title
			})
			
			currentDomain := ""
			for _, result := range passkeyResults {
				domain := g.extractDomain(result.Metadata)
				if domain != currentDomain {
					currentDomain = domain
					fmt.Fprintf(writer, "  %s:\n", domain)
				}
				fmt.Fprintf(writer, "    - %s\n", result.Title)
			}
			fmt.Fprintln(writer)
		}
		}

	return nil
}

// generateRecommendations 生成安全建议
func (g *TableGenerator) generateRecommendations(writer io.Writer, report *types.AuditReport) {
	fmt.Fprintln(writer, "=== SECURITY RECOMMENDATIONS ===")
	
	hasIssues := false
	
	// 2FA建议
	if count, exists := report.Summary.ByType[types.DetectionMissing2FA]; exists && count > 0 {
		hasIssues = true
		fmt.Fprintf(writer, "• Enable 2FA: %d accounts need two-factor authentication\n", count)
	}
	
	// Passkey建议
	if count, exists := report.Summary.ByType[types.DetectionMissingPasskey]; exists && count > 0 {
		hasIssues = true
		fmt.Fprintf(writer, "• Use Passkeys: %d accounts can upgrade to passwordless authentication\n", count)
	}
	
	if !hasIssues {
		fmt.Fprintln(writer, "✅ All credentials are following security best practices!")
	}
	
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "For detailed setup instructions, visit the documentation URLs in the JSON report.")
}

// formatDetectionType 格式化检测类型
func (g *TableGenerator) formatDetectionType(detectionType types.DetectionType) string {
	switch detectionType {
	case types.DetectionMissing2FA:
		return "Missing 2FA"
	case types.DetectionMissingPasskey:
		return "Missing Passkey"
	default:
		return string(detectionType)
	}
}

// formatSeverity 格式化严重程度
func (g *TableGenerator) formatSeverity(severity types.Severity) string {
	switch severity {
	case types.SeverityHigh:
		return "HIGH"
	case types.SeverityMedium:
		return "MEDIUM"
	default:
		return string(severity)
	}
}

// formatTitle 格式化标题显示，考虑中文字符宽度
func (g *TableGenerator) formatTitle(title string) string {
	if title == "" {
		return "-"
	}
	
	const maxDisplayWidth = 30
	currentWidth := g.displayWidth(title)
	
	if currentWidth <= maxDisplayWidth {
		return title
	}
	
	// 需要截断，确保截断后的宽度不超过限制
	result := ""
	width := 0
	for _, r := range title {
		charWidth := 1
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) {
			charWidth = 2
		}
		
		if width + charWidth + 3 > maxDisplayWidth { // 3是"..."的宽度
			break
		}
		
		result += string(r)
		width += charWidth
	}
	
	return result + "..."
}

// truncateString 截断字符串
func (g *TableGenerator) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// extractDomain 从元数据中提取域名
func (g *TableGenerator) extractDomain(metadata map[string]interface{}) string {
	if domain, exists := metadata["domain"]; exists {
		if domainStr, ok := domain.(string); ok {
			return domainStr
		}
	}
	return "-"
}

// extractOriginalURL 从元数据中提取原始URL
func (g *TableGenerator) extractOriginalURL(metadata map[string]interface{}) string {
	if url, exists := metadata["original_url"]; exists {
		if urlStr, ok := url.(string); ok {
			// 不截断URL，让它自然换行
			return urlStr
		}
	}
	return "-"
} 

// displayWidth 计算字符串的显示宽度（中文字符算2个宽度）
func (g *TableGenerator) displayWidth(s string) int {
	width := 0
	for _, r := range s {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) {
			width += 2 // 中文、日文字符占2个显示位置
		} else {
			width += 1 // 其他字符占1个显示位置
		}
	}
	return width
}

// padString 填充字符串到指定显示宽度
func (g *TableGenerator) padString(s string, targetWidth int) string {
	currentWidth := g.displayWidth(s)
	if currentWidth >= targetWidth {
		return s
	}
	padding := targetWidth - currentWidth
	return s + strings.Repeat(" ", padding)
} 