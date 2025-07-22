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
		hostedZone := d.domainMatcher.ExtractHostedZone(cred.URL)
		if hostedZone == "" {
			continue
		}
		
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
					"domain":        hostedZone,
					"original_url":  cred.URL,
					"site_name":     site.Name,
					"support_type":  supportType,
					"setup_link":    site.SetupLink,
					"category":      site.Category,
				},
			})
		}
	}
	
	return results, nil
}

func (d *PasskeyDetector) Configure(config map[string]interface{}) error {
	return nil
} 