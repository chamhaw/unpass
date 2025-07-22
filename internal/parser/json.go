package parser

import (
	"encoding/json"
	"io"
	"github.com/yourorg/unpass/internal/types"
)

type JSONParser struct{}

func NewJSONParser() *JSONParser {
	return &JSONParser{}
}

func (p *JSONParser) Name() string {
	return "json"
}

func (p *JSONParser) Parse(reader io.Reader) ([]types.Credential, error) {
	var credentials []types.Credential
	decoder := json.NewDecoder(reader)
	
	if err := decoder.Decode(&credentials); err != nil {
		return nil, err
	}
	
	return credentials, nil
}

func (p *JSONParser) SupportedFormats() []string {
	return []string{"json"}
} 