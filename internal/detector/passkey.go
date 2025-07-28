package detector

import (
	"context"
	"strings"

	"github.com/yourorg/unpass/internal/database"
	"github.com/yourorg/unpass/internal/domain"
	"github.com/yourorg/unpass/internal/types"
)

type PasskeyDetector struct {
	supportedDomains map[string]types.PasskeySite
	domainMatcher    *domain.DomainMatcher
}

func NewPasskeyDetector(dbLoader *database.DatabaseLoader) (*PasskeyDetector, error) {
	passkeyDB, err := dbLoader.LoadPasskeyDatabase()
	if err != nil {
		return nil, err
	}

	// 加载2FA数据库用于域名匹配器
	twofaDB, _ := dbLoader.LoadTwoFADatabase() // 忽略错误，可能不存在

	supportedDomains := make(map[string]types.PasskeySite)
	for _, site := range *passkeyDB {
		if site.Approved && !site.Hidden && (site.PasskeySignin || site.PasskeyMFA) {
			supportedDomains[strings.ToLower(site.Domain)] = site
		}
	}

	return &PasskeyDetector{
		supportedDomains: supportedDomains,
		domainMatcher:    domain.NewDomainMatcher(twofaDB, passkeyDB),
	}, nil
}

func (d *PasskeyDetector) Name() string {
	return "passkey"
}

func (d *PasskeyDetector) Detect(ctx context.Context, creds []types.Credential) ([]types.DetectionResult, error) {
	var results []types.DetectionResult

	for _, cred := range creds {
		// 如果已经配置了Passkey，跳过检测
		if cred.Passkey != "" {
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
				var supportType string
				if site.PasskeySignin {
					supportType = "signin"
				} else if site.PasskeyMFA {
					supportType = "mfa"
				}

				results = append(results, types.DetectionResult{
					CredentialID: cred.ID,
					Title:        cred.Title,
					Type:         types.DetectionMissingPasskey,
					Severity:     types.SeverityMedium,
					Message:      "Website supports Passkey but traditional password is still used",
					Metadata: map[string]interface{}{
						"domain":       hostedZone,
						"original_url": url,
						"site_name":    site.Name,
						"support_type": supportType,
						"setup_link":   site.SetupLink,
					},
				})
			}
		}
	}

	return results, nil
}

func (d *PasskeyDetector) Configure(config map[string]interface{}) error {
	return nil
}
