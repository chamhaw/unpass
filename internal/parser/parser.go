package parser

import (
	"io"
	"github.com/yourorg/unpass/internal/types"
)

type Parser interface {
	Name() string
	Parse(reader io.Reader) ([]types.Credential, error)
	SupportedFormats() []string
}

type Registry struct {
	parsers map[string]Parser
}

func NewRegistry() *Registry {
	return &Registry{
		parsers: make(map[string]Parser),
	}
}

func (r *Registry) Register(name string, parser Parser) {
	r.parsers[name] = parser
}

func (r *Registry) Get(name string) (Parser, bool) {
	parser, exists := r.parsers[name]
	return parser, exists
}

func (r *Registry) GetByFormat(format string) Parser {
	for _, parser := range r.parsers {
		for _, supportedFormat := range parser.SupportedFormats() {
			if supportedFormat == format {
				return parser
			}
		}
	}
	return nil
} 