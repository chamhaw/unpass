package types

// ReportFormat 报告格式枚举
type ReportFormat string

const (
	ReportFormatJSON  ReportFormat = "json"
	ReportFormatTable ReportFormat = "table"
)

// ReportConfig 报告配置
type ReportConfig struct {
	Format     ReportFormat `yaml:"format"`
	OutputFile string       `yaml:"output_file"`
} 