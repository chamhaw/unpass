package audit

import (
	"context"
	"fmt"
	"time"
	"github.com/yourorg/unpass/internal/detector"
	"github.com/yourorg/unpass/internal/types"
)

type Engine struct {
	detectors []detector.Detector
}

func NewEngine() *Engine {
	return &Engine{
		detectors: make([]detector.Detector, 0),
	}
}

func (e *Engine) RegisterDetector(det detector.Detector) {
	e.detectors = append(e.detectors, det)
}

func (e *Engine) Audit(ctx context.Context, creds []types.Credential) (*types.AuditReport, error) {
	var allResults []types.DetectionResult
	
	for _, det := range e.detectors {
		results, err := det.Detect(ctx, creds)
		if err != nil {
			return nil, fmt.Errorf("detector %s failed: %w", det.Name(), err)
		}
		allResults = append(allResults, results...)
	}
	
	summary := types.AuditSummary{
		TotalCredentials: len(creds),
		IssuesFound:      len(allResults),
		ByType:           make(map[types.DetectionType]int),
	}
	
	for _, result := range allResults {
		summary.ByType[result.Type]++
	}
	
	return &types.AuditReport{
		Results:   allResults,
		Summary:   summary,
		Timestamp: time.Now(),
	}, nil
} 
