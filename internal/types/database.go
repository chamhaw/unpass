package types

import "time"

// 2FA数据库结构
type TwoFADatabase struct {
	Description string     `json:"description"`
	LastUpdated string     `json:"last_updated"`
	Sites       []TwoFASite `json:"sites"`
}

type TwoFASite struct {
	Domain           string   `json:"domain"`
	Supports2FA      bool     `json:"supports_2fa"`
	Methods          []string `json:"methods"`
	DocumentationURL string   `json:"documentation_url"`
}

// Passkey数据库结构
type PasskeyDatabase []PasskeySite

type PasskeySite struct {
	ID                int       `json:"id"`
	CreatedAt         time.Time `json:"created_at"`
	Name              string    `json:"name"`
	Domain            string    `json:"domain"`
	Approved          bool      `json:"approved"`
	DomainFull        string    `json:"domain_full"`
	PasskeySignin     bool      `json:"passkey_signin"`
	PasskeyMFA        bool      `json:"passkey_mfa"`
	SetupLink         string    `json:"setup_link"`
	DocumentationLink *string   `json:"documentation_link"`
	Category          string    `json:"category"`
	Notes             *string   `json:"notes"`
	UpdatedAt         time.Time `json:"updated_at"`
	AuthID            string    `json:"auth_id"`
	Hidden            bool      `json:"hidden"`
	WTIncluded        bool      `json:"wt_included"`
}

// pwned密码数据库结构
type PwnedPasswordDatabase struct {
	Description string         `json:"description"`
	LastUpdated string         `json:"last_updated"`
	Passwords   map[string]int `json:"passwords"`
} 