package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yourorg/unpass/internal/audit"
	"github.com/yourorg/unpass/internal/config"
	"github.com/yourorg/unpass/internal/database"
	"github.com/yourorg/unpass/internal/detector"
	"github.com/yourorg/unpass/internal/parser"
	"github.com/yourorg/unpass/internal/providers"
	"github.com/yourorg/unpass/internal/report"
	"github.com/yourorg/unpass/internal/types"
)

var (
	inputFile    string
	outputFile   string
	databasePath string
	format       string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "unpass",
	Short: "Password audit tool for 2FA and Passkey detection",
	Long:  `UnPass detects missing 2FA and Passkey support in password databases using authoritative data sources.`,
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit password database for 2FA and Passkey support",
	RunE:  runAudit,
}

func init() {
	auditCmd.Flags().StringVarP(&inputFile, "file", "f", "", "Input credential file (JSON format)")
	auditCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	auditCmd.Flags().StringVarP(&databasePath, "database", "d", "database", "Database directory path")
	auditCmd.Flags().StringVarP(&format, "format", "", "table", "Output format (json, table)")
	auditCmd.MarkFlagRequired("file")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	cfg := config.DefaultConfig()
	engine := audit.NewEngine()

	// Initialize database loader
	dbLoader := database.NewDatabaseLoader(databasePath)

	// Register core detectors with database support
	if cfg.Detectors.TwoFA {
		twofaDetector, err := detector.NewTwoFADetector(dbLoader)
		if err != nil {
			return fmt.Errorf("failed to initialize 2FA detector: %w", err)
		}
		engine.RegisterDetector(twofaDetector)
	}
	
	if cfg.Detectors.Passkey {
		passkeyDetector, err := detector.NewPasskeyDetector(dbLoader)
		if err != nil {
			return fmt.Errorf("failed to initialize Passkey detector: %w", err)
		}
		engine.RegisterDetector(passkeyDetector)
	}

	// Parse input file
	credentials, err := parseInputFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to parse input file: %w", err)
	}

	fmt.Printf("Loaded %d credentials from %s\n", len(credentials), inputFile)

	// Run audit
	auditReport, err := engine.Audit(context.Background(), credentials)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	// Generate report
	if err := generateReport(auditReport, outputFile, format); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}

func parseInputFile(filename string) ([]types.Credential, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".json" {
		return nil, fmt.Errorf("only JSON format is supported")
	}

	// 创建解析器注册表
	parserRegistry := parser.NewRegistry()
	parserRegistry.Register("json", parser.NewJSONParser())
	
	// 注册providers
	parserRegistry.Register("enpass", providers.NewEnpassParser())

	// 首先尝试通用JSON解析器
	jsonParser := parser.NewJSONParser()
	credentials, err := jsonParser.Parse(file)
	if err == nil && len(credentials) > 0 {
		return credentials, nil
	}

	// 如果通用JSON解析失败，尝试Enpass解析器
	file.Seek(0, 0) // 重置文件指针
	enpassParser := providers.NewEnpassParser()
	return enpassParser.Parse(file)
}

func generateReport(auditReport *types.AuditReport, outputFile, format string) error {
	var writer io.Writer
	if outputFile == "" {
		writer = os.Stdout
	} else {
		file, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		defer file.Close()
		writer = file
	}

	switch format {
	case "json":
		generator := report.NewJSONGenerator()
		return generator.Generate(writer, auditReport)
	case "table":
		generator := report.NewTableGenerator()
		return generator.Generate(writer, auditReport)
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, table)", format)
	}
} 