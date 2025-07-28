package detector

import (
	"context"
	"strings"

	"github.com/yourorg/unpass/internal/database"
	"github.com/yourorg/unpass/internal/domain"
	"github.com/yourorg/unpass/internal/types"
)

type TwoFADetector struct {
	supportedDomains map[string]types.TwoFASite
	domainMatcher    *domain.DomainMatcher
}

func NewTwoFADetector(dbLoader *database.DatabaseLoader) (*TwoFADetector, error) {
	twofaDB, err := dbLoader.LoadTwoFADatabase()
	if err != nil {
		return nil, err
	}

	// 加载Passkey数据库用于域名匹配器
	passkeyDB, _ := dbLoader.LoadPasskeyDatabase() // 忽略错误，可能不存在

	supportedDomains := make(map[string]types.TwoFASite)
	for _, site := range twofaDB.Sites {
		if site.Supports2FA {
			supportedDomains[strings.ToLower(site.Domain)] = site
		}
	}

	return &TwoFADetector{
		supportedDomains: supportedDomains,
		domainMatcher:    domain.NewDomainMatcher(twofaDB, passkeyDB),
	}, nil
}

func (d *TwoFADetector) Name() string {
	return "twofa"
}

func (d *TwoFADetector) Detect(ctx context.Context, creds []types.Credential) ([]types.DetectionResult, error) {
	var results []types.DetectionResult

	for _, cred := range creds {
		// 如果已经配置了TOTP，跳过检测
		if cred.TOTP != "" {
			continue
		}

		// 收集所有需要检查的URL
		urlsToCheck := make([]string, 0)

		// 优先使用 URLs 字段（如果存在）
		if len(cred.URLs) > 0 {
			urlsToCheck = append(urlsToCheck, cred.URLs...)
		} else if cred.URL != "" {
			// 回退到主 URL 字段以保持向后兼容
			urlsToCheck = append(urlsToCheck, cred.URL)
		}

		// 用于去重的 map
		detectedDomains := make(map[string]bool)

		for _, url := range urlsToCheck {
			hostedZone := d.domainMatcher.ExtractHostedZone(url)
			if hostedZone == "" {
				continue
			}

			// 避免重复检测相同域名
			if detectedDomains[hostedZone] {
				continue
			}
			detectedDomains[hostedZone] = true

			if site, exists := d.supportedDomains[hostedZone]; exists {
				results = append(results, types.DetectionResult{
					CredentialID: cred.ID,
					Title:        cred.Title,
					Type:         types.DetectionMissing2FA,
					Severity:     types.SeverityMedium,
					Message:      "Website supports 2FA but may not be enabled",
					Metadata: map[string]interface{}{
						"domain":            hostedZone,
						"original_url":      url,
						"supported_methods": site.Methods,
						"documentation_url": site.DocumentationURL,
					},
				})
			}
		}
	}

	return results, nil
}

func (d *TwoFADetector) Configure(config map[string]interface{}) error {
	return nil
}
