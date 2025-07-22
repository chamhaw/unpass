package types

import "time"

type DetectionType string

const (
	DetectionMissing2FA     DetectionType = "missing_2fa"
	DetectionMissingPasskey DetectionType = "missing_passkey"
)

type Severity string

const (
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// DetectionResult 检测结果
type DetectionResult struct {
	CredentialID string                 `json:"credential_id"`
	Title        string                 `json:"title"`
	Type         DetectionType          `json:"type"`
	Severity     Severity               `json:"severity"`
	Message      string                 `json:"message"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type AuditReport struct {
	Results   []DetectionResult `json:"results"`
	Summary   AuditSummary     `json:"summary"`
	Timestamp time.Time        `json:"timestamp"`
}

type AuditSummary struct {
	TotalCredentials int                    `json:"total_credentials"`
	IssuesFound      int                    `json:"issues_found"`
	ByType           map[DetectionType]int  `json:"by_type"`
} 