package report

import (
	"encoding/json"
	"io"
	"github.com/yourorg/unpass/internal/types"
)

type JSONGenerator struct{}

func NewJSONGenerator() *JSONGenerator {
	return &JSONGenerator{}
}

func (g *JSONGenerator) Generate(writer io.Writer, report *types.AuditReport) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
} 