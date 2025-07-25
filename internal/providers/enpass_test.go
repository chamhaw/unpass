package providers

import (
	"strings"
	"testing"
)

func TestEnpassParser_Parse(t *testing.T) {
	parser := NewEnpassParser()

	testJSON := `{
		"items": [
			{
				"archived": 0,
				"category": "login",
				"title": "GitHub Account",
				"uuid": "test-uuid-1",
				"trashed": 0,
				"fields": [
					{
						"deleted": 0,
						"type": "username",
						"value": "testuser",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "password", 
						"value": "testpass123",
						"sensitive": 1
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://github.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "email",
						"value": "test@example.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "phone",
						"value": "+86-12345678901",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "totp",
						"value": "JBSWY3DPEHPK3PXP",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "text",
						"label": "Security Question",
						"value": "My first pet name",
						"sensitive": 1
					}
				]
			},
			{
				"archived": 1,
				"category": "login",
				"title": "Archived Account",
				"uuid": "test-uuid-2",
				"trashed": 0,
				"fields": [
					{
						"deleted": 0,
						"type": "username",
						"value": "archived",
						"sensitive": 0
					}
				]
			},
			{
				"archived": 0,
				"category": "note",
				"title": "Some Note",
				"uuid": "test-uuid-3",
				"trashed": 0,
				"fields": []
			},
			{
				"archived": 0,
				"category": "login",
				"title": "Email Only Account",
				"uuid": "test-uuid-4",
				"trashed": 0,
				"fields": [
					{
						"deleted": 0,
						"type": "email",
						"value": "user@example.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "password",
						"value": "emailpass",
						"sensitive": 1
					}
				]
			}
		]
	}`

	reader := strings.NewReader(testJSON)
	credentials, err := parser.Parse(reader)

	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// 应该只有2个有效凭据（跳过archived和非login的）
	if len(credentials) != 2 {
		t.Errorf("Expected 2 credentials, got %d", len(credentials))
	}

	// 验证第一个凭据（包含所有字段类型）
	cred1 := credentials[0]
	if cred1.ID != "test-uuid-1" {
		t.Errorf("Expected ID 'test-uuid-1', got '%s'", cred1.ID)
	}
	if cred1.Title != "GitHub Account" {
		t.Errorf("Expected title 'GitHub Account', got '%s'", cred1.Title)
	}
	if cred1.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", cred1.Username)
	}
	if cred1.Password != "testpass123" {
		t.Errorf("Expected password 'testpass123', got '%s'", cred1.Password)
	}
	if cred1.URL != "https://github.com" {
		t.Errorf("Expected URL 'https://github.com', got '%s'", cred1.URL)
	}

	// 验证URLs字段
	if len(cred1.URLs) != 1 {
		t.Errorf("Expected 1 URL in URLs, got %d", len(cred1.URLs))
	} else if cred1.URLs[0] != "https://github.com" {
		t.Errorf("Expected URLs[0] 'https://github.com', got '%s'", cred1.URLs[0])
	}

	// 验证备注字段包含所有额外信息
	expectedNotes := []string{"Email: test@example.com", "Phone: +86-12345678901", "TOTP: JBSWY3DPEHPK3PXP", "Security Question: My first pet name"}
	for _, note := range expectedNotes {
		if !strings.Contains(cred1.Notes, note) {
			t.Errorf("Expected notes to contain '%s', got '%s'", note, cred1.Notes)
		}
	}

	// 验证第二个凭据（email作为username）
	cred2 := credentials[1]
	if cred2.Username != "user@example.com" {
		t.Errorf("Expected username 'user@example.com', got '%s'", cred2.Username)
	}
}

func TestEnpassParser_MultipleURLs(t *testing.T) {
	parser := NewEnpassParser()

	testJSON := `{
		"items": [
			{
				"archived": 0,
				"category": "login",
				"title": "Multi-Domain Account",
				"uuid": "test-multi-url",
				"trashed": 0,
				"fields": [
					{
						"deleted": 0,
						"type": "username",
						"value": "multiuser",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "password",
						"value": "multipass123",
						"sensitive": 1
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://app.example.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://dashboard.example.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://admin.example.com",
						"sensitive": 0
					}
				]
			}
		]
	}`

	reader := strings.NewReader(testJSON)
	credentials, err := parser.Parse(reader)

	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(credentials) != 1 {
		t.Fatalf("Expected 1 credential, got %d", len(credentials))
	}

	cred := credentials[0]

	// 验证基本信息
	if cred.ID != "test-multi-url" {
		t.Errorf("Expected ID 'test-multi-url', got '%s'", cred.ID)
	}
	if cred.Title != "Multi-Domain Account" {
		t.Errorf("Expected title 'Multi-Domain Account', got '%s'", cred.Title)
	}
	if cred.Username != "multiuser" {
		t.Errorf("Expected username 'multiuser', got '%s'", cred.Username)
	}
	if cred.Password != "multipass123" {
		t.Errorf("Expected password 'multipass123', got '%s'", cred.Password)
	}

	// 验证主URL（向后兼容性）
	if cred.URL != "https://app.example.com" {
		t.Errorf("Expected URL 'https://app.example.com', got '%s'", cred.URL)
	}

	// 验证所有URLs
	expectedURLs := []string{
		"https://app.example.com",
		"https://dashboard.example.com",
		"https://admin.example.com",
	}

	if len(cred.URLs) != len(expectedURLs) {
		t.Errorf("Expected %d URLs, got %d", len(expectedURLs), len(cred.URLs))
	}

	for i, expectedURL := range expectedURLs {
		if i >= len(cred.URLs) {
			t.Errorf("Missing URL at index %d: expected '%s'", i, expectedURL)
			continue
		}
		if cred.URLs[i] != expectedURL {
			t.Errorf("Expected URLs[%d] '%s', got '%s'", i, expectedURL, cred.URLs[i])
		}
	}
}

func TestEnpassParser_RealWorldMultipleURLs(t *testing.T) {
	parser := NewEnpassParser()

	// 模拟真实场景：一个企业账户可能同时用于多个子域名
	testJSON := `{
		"items": [
			{
				"archived": 0,
				"category": "login",
				"title": "Company Account",
				"uuid": "company-account",
				"trashed": 0,
				"fields": [
					{
						"deleted": 0,
						"type": "username",
						"value": "john@company.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "password",
						"value": "SecurePass123!",
						"sensitive": 1
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://portal.company.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://admin.company.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://api.company.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "url",
						"value": "https://docs.company.com",
						"sensitive": 0
					},
					{
						"deleted": 0,
						"type": "totp",
						"value": "JBSWY3DPEHPK3PXP",
						"sensitive": 0
					}
				]
			}
		]
	}`

	reader := strings.NewReader(testJSON)
	credentials, err := parser.Parse(reader)

	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(credentials) != 1 {
		t.Fatalf("Expected 1 credential, got %d", len(credentials))
	}

	cred := credentials[0]

	// 验证密码项信息
	if cred.Title != "Company Account" {
		t.Errorf("Expected title 'Company Account', got '%s'", cred.Title)
	}
	if cred.Username != "john@company.com" {
		t.Errorf("Expected username 'john@company.com', got '%s'", cred.Username)
	}
	if cred.Password != "SecurePass123!" {
		t.Errorf("Expected password 'SecurePass123!', got '%s'", cred.Password)
	}

	// 验证主URL
	if cred.URL != "https://portal.company.com" {
		t.Errorf("Expected main URL 'https://portal.company.com', got '%s'", cred.URL)
	}

	// 验证所有URLs
	expectedURLs := []string{
		"https://portal.company.com",
		"https://admin.company.com",
		"https://api.company.com",
		"https://docs.company.com",
	}

	if len(cred.URLs) != len(expectedURLs) {
		t.Errorf("Expected %d URLs, got %d: %v", len(expectedURLs), len(cred.URLs), cred.URLs)
	}

	for i, expectedURL := range expectedURLs {
		if i >= len(cred.URLs) || cred.URLs[i] != expectedURL {
			t.Errorf("Expected URLs[%d] '%s', got '%s'", i, expectedURL, cred.URLs[i])
		}
	}

	// 验证TOTP信息被正确放在备注中
	if !strings.Contains(cred.Notes, "TOTP: JBSWY3DPEHPK3PXP") {
		t.Errorf("Expected notes to contain TOTP information, got '%s'", cred.Notes)
	}
}

func TestEnpassParser_ShouldProcessItem(t *testing.T) {
	parser := NewEnpassParser()

	testCases := []struct {
		name     string
		item     EnpassItem
		expected bool
	}{
		{
			name: "valid login item",
			item: EnpassItem{
				Archived: 0,
				Category: "login",
				Trashed:  0,
			},
			expected: true,
		},
		{
			name: "archived item",
			item: EnpassItem{
				Archived: 1,
				Category: "login",
				Trashed:  0,
			},
			expected: false,
		},
		{
			name: "trashed item",
			item: EnpassItem{
				Archived: 0,
				Category: "login",
				Trashed:  1,
			},
			expected: false,
		},
		{
			name: "non-login category",
			item: EnpassItem{
				Archived: 0,
				Category: "note",
				Trashed:  0,
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parser.shouldProcessItem(tc.item)
			if result != tc.expected {
				t.Errorf("shouldProcessItem() = %v, expected %v", result, tc.expected)
			}
		})
	}
}

func TestEnpassParser_CleanURL(t *testing.T) {
	parser := NewEnpassParser()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal URL",
			input:    "https://github.com",
			expected: "https://github.com",
		},
		{
			name:     "long callback URL",
			input:    "http://www.19lou.com/outsite/callback?code=021hS1bL0EvII62h7z8L06zZaL0hS1b5&param=YXBwVHlwZT1XZWl4aW4mY2l0eT1oYW5nemhvdQ==",
			expected: "http://www.19lou.com",
		},
		{
			name:     "empty URL",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parser.cleanURL(tc.input)
			if result != tc.expected {
				t.Errorf("cleanURL(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}
