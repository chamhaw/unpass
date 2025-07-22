package domain

import (
	"testing"
	"github.com/yourorg/unpass/internal/types"
)

func TestDomainMatcher_ExtractHostedZone(t *testing.T) {
	// 创建模拟数据库
	twofaDB := &types.TwoFADatabase{
		Sites: []types.TwoFASite{
			{Domain: "github.com", Supports2FA: true},
			{Domain: "google.com", Supports2FA: true},
			{Domain: "microsoft.com", Supports2FA: true},
			{Domain: "apple.com", Supports2FA: true},
		},
	}
	
	passkeyDB := &types.PasskeyDatabase{
		{Domain: "github.com", Approved: true, Hidden: false, PasskeySignin: true},
		{Domain: "google.com", Approved: true, Hidden: false, PasskeySignin: true},
	}
	
	matcher := NewDomainMatcher(twofaDB, passkeyDB)
	
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		// 基础域名测试
		{
			name:     "simple domain",
			input:    "https://github.com",
			expected: "github.com",
		},
		{
			name:     "domain without scheme",
			input:    "github.com",
			expected: "github.com",
		},
		
		// www子域名测试
		{
			name:     "www subdomain",
			input:    "https://www.github.com",
			expected: "github.com",
		},
		{
			name:     "www without scheme",
			input:    "www.google.com",
			expected: "google.com",
		},
		
		// 子域名智能匹配测试
		{
			name:     "github api subdomain",
			input:    "https://api.github.com/v3",
			expected: "github.com",
		},
		{
			name:     "google accounts subdomain",
			input:    "https://accounts.google.com/login",
			expected: "google.com",
		},
		{
			name:     "unknown subdomain of known domain",
			input:    "https://unknown.github.com",
			expected: "github.com",
		},
		{
			name:     "deep subdomain",
			input:    "https://sub.api.github.com",
			expected: "github.com",
		},
		
		// 路径和参数测试
		{
			name:     "github with path",
			input:    "https://github.com/user/repo",
			expected: "github.com",
		},
		{
			name:     "google with query params",
			input:    "https://google.com/search?q=test",
			expected: "google.com",
		},
		
		// 边界情况测试
		{
			name:     "empty URL",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid URL",
			input:    "not-a-url",
			expected: "not-a-url",
		},
		{
			name:     "unknown domain",
			input:    "https://unknown-domain.example",
			expected: "unknown-domain.example",
		},
		
		// 恶意域名测试（不应该误匹配）
		{
			name:     "evil domain should not match",
			input:    "https://evil-github.com",
			expected: "evil-github.com",
		},
		{
			name:     "github lookalike",
			input:    "https://github-fake.com",
			expected: "github-fake.com",
		},
		
		// 二级域名默认处理
		{
			name:     "unknown second level domain",
			input:    "https://example.co.uk",
			expected: "co.uk",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := matcher.ExtractHostedZone(tc.input)
			if result != tc.expected {
				t.Errorf("ExtractHostedZone(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestDomainMatcher_DatabaseDriven(t *testing.T) {
	// 测试基于数据库的域名识别
	twofaDB := &types.TwoFADatabase{
		Sites: []types.TwoFASite{
			{Domain: "example.com", Supports2FA: true},
			{Domain: "test.org", Supports2FA: true},
		},
	}
	
	passkeyDB := &types.PasskeyDatabase{
		{Domain: "secure.net", Approved: true, Hidden: false, PasskeySignin: true},
	}
	
	matcher := NewDomainMatcher(twofaDB, passkeyDB)
	
	// 测试数据库中的域名能被正确识别
	testCases := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"https://sub.example.com", "example.com"},
		{"https://api.test.org", "test.org"},
		{"https://secure.net", "secure.net"},
		{"https://unknown.secure.net", "secure.net"},
	}
	
	for _, tc := range testCases {
		result := matcher.ExtractHostedZone(tc.input)
		if result != tc.expected {
			t.Errorf("ExtractHostedZone(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
} 