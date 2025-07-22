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
		hostedZone := d.domainMatcher.ExtractHostedZone(cred.URL)
		if hostedZone == "" {
			continue
		}
		
		if site, exists := d.supportedDomains[hostedZone]; exists {
			results = append(results, types.DetectionResult{
				CredentialID: cred.ID,
				Title:        cred.Title,
				Type:         types.DetectionMissing2FA,
				Severity:     types.SeverityMedium,
				Message:      "Website supports 2FA but may not be enabled",
				Metadata: map[string]interface{}{
					"domain":              hostedZone,
					"original_url":        cred.URL,
					"supported_methods":   site.Methods,
					"documentation_url":   site.DocumentationURL,
				},
			})
		}
	}
	
	return results, nil
}

func (d *TwoFADetector) Configure(config map[string]interface{}) error {
	return nil
} 