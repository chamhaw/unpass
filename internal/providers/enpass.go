package providers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/yourorg/unpass/internal/types"
)

// EnpassFieldType Enpass字段类型枚举
type EnpassFieldType string

const (
	FieldTypeUsername EnpassFieldType = "username"
	FieldTypePassword EnpassFieldType = "password"
	FieldTypeURL      EnpassFieldType = "url"
	FieldTypeEmail    EnpassFieldType = "email"
	FieldTypePhone    EnpassFieldType = "phone"
	FieldTypeTOTP     EnpassFieldType = "totp"
	FieldTypeText     EnpassFieldType = "text"
)

// FieldTypeMapping 字段类型映射配置
type FieldTypeMapping struct {
	Type        EnpassFieldType
	Priority    int  // 优先级，数字越小优先级越高
	IsPrimary   bool // 是否为主要字段（直接映射到credential结构）
	IsNoteField bool // 是否需要添加到备注中
}

// fieldTypeMappings 字段类型映射表
var fieldTypeMappings = map[EnpassFieldType]FieldTypeMapping{
	FieldTypeUsername: {Type: FieldTypeUsername, Priority: 1, IsPrimary: true, IsNoteField: false},
	FieldTypePassword: {Type: FieldTypePassword, Priority: 1, IsPrimary: true, IsNoteField: false},
	FieldTypeURL:      {Type: FieldTypeURL, Priority: 1, IsPrimary: true, IsNoteField: false},
	FieldTypeEmail:    {Type: FieldTypeEmail, Priority: 2, IsPrimary: false, IsNoteField: true},
	FieldTypePhone:    {Type: FieldTypePhone, Priority: 3, IsPrimary: false, IsNoteField: true},
	FieldTypeTOTP:     {Type: FieldTypeTOTP, Priority: 3, IsPrimary: false, IsNoteField: true},
	FieldTypeText:     {Type: FieldTypeText, Priority: 4, IsPrimary: false, IsNoteField: true},
}

// EnpassData Enpass导出的原始数据结构
type EnpassData struct {
	Items []EnpassItem `json:"items"`
}

type EnpassItem struct {
	Archived int           `json:"archived"`
	Category string        `json:"category"`
	Title    string        `json:"title"`
	UUID     string        `json:"uuid"`
	Trashed  int           `json:"trashed"`
	Fields   []EnpassField `json:"fields"`
}

type EnpassField struct {
	Deleted   int    `json:"deleted"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Sensitive int    `json:"sensitive"`
}

// EnpassParser Enpass数据解析器
type EnpassParser struct{}

func NewEnpassParser() *EnpassParser {
	return &EnpassParser{}
}

func (p *EnpassParser) Name() string {
	return "enpass"
}

func (p *EnpassParser) Parse(reader io.Reader) ([]types.Credential, error) {
	var enpassData EnpassData
	decoder := json.NewDecoder(reader)

	if err := decoder.Decode(&enpassData); err != nil {
		return nil, fmt.Errorf("failed to decode Enpass JSON: %w", err)
	}

	var credentials []types.Credential

	for _, item := range enpassData.Items {
		// 跳过不符合条件的数据
		if !p.shouldProcessItem(item) {
			continue
		}

		// 提取字段数据
		credential := p.extractCredential(item)

		// 验证必要字段
		if p.isValidCredential(credential) {
			credentials = append(credentials, credential)
		}
	}

	return credentials, nil
}

func (p *EnpassParser) SupportedFormats() []string {
	return []string{"enpass"}
}

// shouldProcessItem 判断是否应该处理该项目
func (p *EnpassParser) shouldProcessItem(item EnpassItem) bool {
	// 跳过已归档的数据
	if item.Archived == 1 {
		return false
	}

	// 跳过已删除的数据
	if item.Trashed == 1 {
		return false
	}

	// 只处理login类型的数据
	if item.Category != "login" {
		return false
	}

	return true
}

// extractCredential 从Enpass项目中提取凭据信息
func (p *EnpassParser) extractCredential(item EnpassItem) types.Credential {
	credential := types.Credential{
		ID:    item.UUID,
		Title: item.Title,
	}

	// 用于收集备注信息的字段
	var notes []string
	// 用于收集所有URL
	var urls []string

	// 遍历字段提取所需信息
	for _, field := range item.Fields {
		// 跳过已删除的字段
		if field.Deleted == 1 {
			continue
		}

		// 跳过空值字段
		if strings.TrimSpace(field.Value) == "" {
			continue
		}

		// 处理字段
		p.processField(&credential, &notes, &urls, field)
	}

	// 设置URLs字段和主URL
	if len(urls) > 0 {
		credential.URLs = urls
		credential.URL = urls[0] // 第一个URL作为主URL，保持向后兼容
	}

	// 合并备注信息
	if len(notes) > 0 {
		credential.Notes = strings.Join(notes, "; ")
	}

	return credential
}

// processField 处理单个字段
func (p *EnpassParser) processField(credential *types.Credential, notes *[]string, urls *[]string, field EnpassField) {
	fieldType := EnpassFieldType(field.Type)
	mapping, exists := fieldTypeMappings[fieldType]

	if !exists {
		// 未知字段类型，作为文本字段处理
		if field.Label != "" {
			*notes = append(*notes, fmt.Sprintf("%s: %s", field.Label, field.Value))
		}
		return
	}

	switch fieldType {
	case FieldTypeUsername:
		credential.Username = field.Value

	case FieldTypePassword:
		credential.Password = field.Value

	case FieldTypeURL:
		cleanedURL := p.cleanURL(field.Value)
		if cleanedURL != "" {
			*urls = append(*urls, cleanedURL)
		}

	case FieldTypeEmail:
		// 如果没有username，使用email作为username
		if credential.Username == "" {
			credential.Username = field.Value
		} else if mapping.IsNoteField {
			*notes = append(*notes, fmt.Sprintf("Email: %s", field.Value))
		}

	case FieldTypePhone:
		if mapping.IsNoteField {
			*notes = append(*notes, fmt.Sprintf("Phone: %s", field.Value))
		}

	case FieldTypeTOTP:
		if mapping.IsNoteField {
			*notes = append(*notes, fmt.Sprintf("TOTP: %s", field.Value))
		}

	case FieldTypeText:
		if mapping.IsNoteField && field.Label != "" {
			*notes = append(*notes, fmt.Sprintf("%s: %s", field.Label, field.Value))
		}
	}
}

// cleanURL 清理和标准化URL
func (p *EnpassParser) cleanURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	// 移除过长的URL参数（可能是callback URL）
	if len(rawURL) > 120 {
		// 尝试提取域名部分
		if strings.Contains(rawURL, "://") {
			parts := strings.Split(rawURL, "/")
			if len(parts) >= 3 {
				return parts[0] + "//" + parts[2]
			}
		}
	}

	return rawURL
}

// isValidCredential 验证凭据是否有效
func (p *EnpassParser) isValidCredential(credential types.Credential) bool {
	// 必须有ID和标题
	if credential.ID == "" || credential.Title == "" {
		return false
	}

	// 必须有用户名或密码之一
	if credential.Username == "" && credential.Password == "" {
		return false
	}

	return true
}

// GetSupportedFieldTypes 获取支持的字段类型列表
func GetSupportedFieldTypes() []EnpassFieldType {
	var types []EnpassFieldType
	for fieldType := range fieldTypeMappings {
		types = append(types, fieldType)
	}
	return types
}

// GetFieldTypeMapping 获取字段类型映射配置
func GetFieldTypeMapping(fieldType EnpassFieldType) (FieldTypeMapping, bool) {
	mapping, exists := fieldTypeMappings[fieldType]
	return mapping, exists
}
