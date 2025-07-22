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