package detector

import (
	"context"
	"github.com/yourorg/unpass/internal/types"
)

type Detector interface {
	Name() string
	Detect(ctx context.Context, creds []types.Credential) ([]types.DetectionResult, error)
	Configure(config map[string]interface{}) error
}

type Registry struct {
	detectors map[string]Detector
}

func NewRegistry() *Registry {
	return &Registry{
		detectors: make(map[string]Detector),
	}
}

func (r *Registry) Register(name string, detector Detector) {
	r.detectors[name] = detector
}

func (r *Registry) Get(name string) (Detector, bool) {
	detector, exists := r.detectors[name]
	return detector, exists
}

func (r *Registry) List() []string {
	var names []string
	for name := range r.detectors {
		names = append(names, name)
	}
	return names
} 