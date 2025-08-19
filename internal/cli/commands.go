package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/owaspchecker/internal/attack"
	"github.com/owaspchecker/internal/common"
	"github.com/owaspchecker/internal/crawl"
	"github.com/owaspchecker/internal/har"
	"github.com/owaspchecker/internal/httpx"
	"github.com/owaspchecker/internal/report"
	"github.com/owaspchecker/internal/store"
	"github.com/spf13/cobra"
)

// Commands holds all CLI commands
type Commands struct {
	rootCmd *cobra.Command
	store   *store.SQLiteStore
	client  *httpx.Client
}

// NewCommands creates new CLI commands
func NewCommands() *Commands {
	store, err := store.NewSQLiteStore("owaspchecker.db")
	if err != nil {
		fmt.Printf("Failed to initialize store: %v\n", err)
		os.Exit(1)
	}

	client := httpx.NewClient(store)

	cmds := &Commands{
		store:  store,
		client: client,
	}

	cmds.setupCommands()
	return cmds
}

// setupCommands sets up all CLI commands
func (c *Commands) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:   "owaspchecker",
		Short: "OWASP Top 10 Web Application Security Scanner",
		Long: `OWASPChecker is a comprehensive web application security scanner 
that focuses on OWASP Top 10 vulnerabilities. It can crawl websites, 
load requests from HAR/JSON files, and perform automated security testing.`,
	}

	// Add subcommands
	c.rootCmd.AddCommand(c.crawlCmd())
	c.rootCmd.AddCommand(c.attackCmd())
	c.rootCmd.AddCommand(c.reportCmd())
}

// crawlCmd creates the crawl command
func (c *Commands) crawlCmd() *cobra.Command {
	var depth int

	cmd := &cobra.Command{
		Use:   "crawl [base-url]",
		Short: "Crawl a website to discover links and forms",
		Long:  `Crawl a target website to discover links, forms, and endpoints for security testing.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL := args[0]
			return c.runCrawl(baseURL, depth)
		},
	}

	cmd.Flags().IntVarP(&depth, "depth", "d", 3, "Maximum crawl depth")
	return cmd
}

// attackCmd creates the attack command
func (c *Commands) attackCmd() *cobra.Command {
	var concurrency int

	cmd := &cobra.Command{
		Use:   "attack [requests-file]",
		Short: "Attack requests with security payloads",
		Long:  `Load requests from a file and perform security testing with various payloads.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requestsFile := args[0]
			return c.runAttack(requestsFile, concurrency)
		},
	}

	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 10, "Number of concurrent requests")
	return cmd
}

// reportCmd creates the report command
func (c *Commands) reportCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate security report",
		Long:  `Generate a comprehensive security report from stored findings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runReport(outputFormat)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "markdown", "Output format (markdown, html, json)")
	return cmd
}

// runCrawl executes the crawl operation
func (c *Commands) runCrawl(baseURL string, depth int) error {
	fmt.Printf("Starting crawl of %s with depth %d...\n", baseURL, depth)

	crawler := crawl.NewCrawler(c.client, c.store)
	result, err := crawler.Crawl(baseURL, depth)
	if err != nil {
		return fmt.Errorf("crawl failed: %w", err)
	}

	fmt.Printf("Crawl completed!\n")
	fmt.Printf("  Base URL: %s\n", result.BaseURL)
	fmt.Printf("  Depth: %d\n", result.Depth)
	fmt.Printf("  Requests discovered: %d\n", len(result.Requests))
	fmt.Printf("  Duration: %v\n", result.EndTime.Sub(result.StartTime))

	return nil
}

// runAttack executes the attack operation
func (c *Commands) runAttack(requestsFile string, concurrency int) error {
	fmt.Printf("Loading requests from %s...\n", requestsFile)

	// Load requests from file
	requests, err := c.loadRequests(requestsFile)
	if err != nil {
		return fmt.Errorf("failed to load requests: %w", err)
	}

	fmt.Printf("Loaded %d requests\n", len(requests))

	// Create attack engine
	engine := attack.NewEngine(c.client, c.store, concurrency)

	fmt.Printf("Starting attack with concurrency %d...\n", concurrency)
	result, err := engine.Attack(requests)
	if err != nil {
		return fmt.Errorf("attack failed: %w", err)
	}

	fmt.Printf("Attack completed!\n")
	fmt.Printf("  Original requests: %d\n", len(result.OriginalRequests))
	fmt.Printf("  Mutated requests: %d\n", len(result.MutatedRequests))
	fmt.Printf("  Responses: %d\n", len(result.Responses))
	fmt.Printf("  Findings: %d\n", len(result.Findings))
	fmt.Printf("  Duration: %v\n", result.EndTime.Sub(result.StartTime))

	// Store findings
	for _, finding := range result.Findings {
		if err := c.store.StoreFinding(&finding); err != nil {
			fmt.Printf("Failed to store finding: %v\n", err)
		}
	}

	return nil
}

// runReport generates the security report
func (c *Commands) runReport(outputFormat string) error {
	fmt.Printf("Generating %s report...\n", outputFormat)

	// Get findings from store
	findings, err := c.store.GetFindings()
	if err != nil {
		return fmt.Errorf("failed to get findings: %w", err)
	}

	if len(findings) == 0 {
		fmt.Println("No findings to report.")
		return nil
	}

	// Generate report
	reporter := report.NewReporter()
	outputFile := fmt.Sprintf("owaspchecker_report.%s", getFileExtension(outputFormat))

	config := &common.ReportConfig{
		OutputFormat:    outputFormat,
		OutputFile:      outputFile,
		IncludeEvidence: true,
		GroupBySeverity: true,
	}

	if err := reporter.GenerateReport(findings, config); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	fmt.Printf("Report generated: %s\n", outputFile)
	fmt.Printf("  Total findings: %d\n", len(findings))

	// Print summary
	severityCounts := make(map[common.Severity]int)
	for _, finding := range findings {
		severityCounts[finding.Severity]++
	}

	for severity, count := range severityCounts {
		fmt.Printf("  %s: %d\n", severity, count)
	}

	return nil
}

// loadRequests loads requests from a file
func (c *Commands) loadRequests(filename string) ([]common.RecordedRequest, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	loader := har.NewLoader()
	ext := filepath.Ext(filename)

	switch ext {
	case ".har":
		return loader.LoadHAR(file)
	case ".json":
		return loader.LoadJSON(file)
	default:
		return nil, fmt.Errorf("unsupported file format: %s", ext)
	}
}

// getFileExtension returns the file extension for the output format
func getFileExtension(format string) string {
	switch format {
	case "markdown":
		return "md"
	case "html":
		return "html"
	case "json":
		return "json"
	default:
		return "md"
	}
}

// Execute runs the CLI
func (c *Commands) Execute() error {
	return c.rootCmd.Execute()
}

// Close closes the store
func (c *Commands) Close() error {
	return c.store.Close()
}
