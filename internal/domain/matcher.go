package domain

import (
	"net/url"
	"strings"
	"github.com/yourorg/unpass/internal/types"
)

// DomainMatcher 智能域名匹配器
type DomainMatcher struct {
	// 基于数据库动态生成的域名映射
	knownDomains map[string]bool
}

// NewDomainMatcher 创建域名匹配器
func NewDomainMatcher(twofaDB *types.TwoFADatabase, passkeyDB *types.PasskeyDatabase) *DomainMatcher {
	knownDomains := make(map[string]bool)
	
	// 从2FA数据库提取已知域名
	if twofaDB != nil {
		for _, site := range twofaDB.Sites {
			if site.Supports2FA {
				knownDomains[strings.ToLower(site.Domain)] = true
			}
		}
	}
	
	// 从Passkey数据库提取已知域名
	if passkeyDB != nil {
		for _, site := range *passkeyDB {
			if site.Approved && !site.Hidden {
				knownDomains[strings.ToLower(site.Domain)] = true
			}
		}
	}
	
	return &DomainMatcher{
		knownDomains: knownDomains,
	}
}

// ExtractHostedZone 从URL中提取hosted zone（主域名）
func (dm *DomainMatcher) ExtractHostedZone(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	
	// 标准化URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return ""
	}
	
	// 智能提取主域名
	return dm.extractMainDomain(hostname)
}

// extractMainDomain 智能提取主域名
func (dm *DomainMatcher) extractMainDomain(hostname string) string {
	// 移除www前缀
	if strings.HasPrefix(hostname, "www.") {
		hostname = hostname[4:]
	}
	
	// 首先检查是否为已知域名
	if dm.knownDomains[hostname] {
		return hostname
	}
	
	// 智能匹配：尝试不同的域名层级
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}
	
	// 从右往左尝试匹配已知域名
	for i := 0; i < len(parts)-1; i++ {
		possibleDomain := strings.Join(parts[i:], ".")
		if dm.knownDomains[possibleDomain] {
			return possibleDomain
		}
	}
	
	// 如果没有匹配到已知域名，返回二级域名
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	
	return hostname
} 