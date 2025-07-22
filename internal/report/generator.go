package report

import (
	"io"
	"github.com/yourorg/unpass/internal/types"
)

type Generator interface {
	Generate(report *types.AuditReport, writer io.Writer) error
} 