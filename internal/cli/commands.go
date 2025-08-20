package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/owaspchecker/internal/attack"
	"github.com/owaspchecker/internal/common"
	"github.com/owaspchecker/internal/crawl"
	"github.com/owaspchecker/internal/har"
	"github.com/owaspchecker/internal/httpx"
	"github.com/owaspchecker/internal/report"
	"github.com/owaspchecker/internal/store"
	"github.com/schollz/progressbar/v3"
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
		Use:   "owaspchecker [URL or requests-file]",
		Short: "OWASP Top 10 Web Application Security Scanner",
		Long: `OWASPChecker is a comprehensive web application security scanner 
that focuses on OWASP Top 10 vulnerabilities.

Usage:
  owaspchecker <URL>                    # Attack a website directly
  owaspchecker <requests-file>          # Attack requests from HAR/JSON file
  owaspchecker --help                   # Show help

Examples:
  owaspchecker https://example.com
  owaspchecker requests.har
  owaspchecker requests.json`,
		Args: cobra.MaximumNArgs(1),
		RunE: c.runMain,
	}

	// Add flags
	c.rootCmd.Flags().IntP("depth", "d", 3, "Maximum crawl depth (only for URL)")
	c.rootCmd.Flags().IntP("concurrency", "c", 10, "Number of concurrent requests")
	c.rootCmd.Flags().StringP("format", "f", "html", "Report format (html, json)")
	c.rootCmd.Flags().BoolP("crawl-only", "", false, "Only crawl, don't attack")
	c.rootCmd.Flags().BoolP("attack-only", "", false, "Only attack, don't crawl")
	c.rootCmd.Flags().Bool("clean", false, "Clean database before starting new scan")
	c.rootCmd.Flags().IntP("delay", "", 0, "Delay between requests in milliseconds (for rate limiting tests)")
	c.rootCmd.Flags().IntP("burst", "", 1, "Number of requests to send in burst before delay")
}

// runMain handles the main command execution
func (c *Commands) runMain(cmd *cobra.Command, args []string) error {
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	format, _ := cmd.Flags().GetString("format")
	clean, _ := cmd.Flags().GetBool("clean")
	delay, _ := cmd.Flags().GetInt("delay")
	burst, _ := cmd.Flags().GetInt("burst")

	// If no arguments provided, show help
	if len(args) == 0 {
		return cmd.Help()
	}

	input := args[0]

	// Print banner
	c.printBanner()

	// Clean database if requested
	if clean {
		color.Yellow("🧹 Cleaning database...")
		if err := c.store.CleanDatabase(); err != nil {
			color.Red("❌ Failed to clean database: %v", err)
			return fmt.Errorf("failed to clean database: %w", err)
		}
		color.Green("✅ Database cleaned successfully!")
	}

	// Check if input is a URL or file
	if c.isURL(input) {
		// URL provided - attack directly
		color.Cyan("🔍 Starting direct attack on URL: %s", input)
		if delay > 0 {
			color.Yellow("⏱️ Delay between requests: %dms (burst: %d)", delay, burst)
		}

		if err := c.runAttackURL(input, concurrency, delay, burst); err != nil {
			color.Red("❌ Attack failed: %v", err)
			return fmt.Errorf("attack failed: %w", err)
		}
	} else {
		// File provided - attack from file
		color.Cyan("🔍 Loading requests from file: %s", input)
		if delay > 0 {
			color.Yellow("⏱️ Delay between requests: %dms (burst: %d)", delay, burst)
		}

		if err := c.runAttack(input, concurrency, delay, burst); err != nil {
			color.Red("❌ Attack failed: %v", err)
			return fmt.Errorf("attack failed: %w", err)
		}
	}

	// Generate report
	color.Cyan("📊 Generating security report...")
	if err := c.runReport(format); err != nil {
		color.Red("❌ Report generation failed: %v", err)
		return fmt.Errorf("report generation failed: %w", err)
	}

	color.Green("✅ Security scan completed successfully!")
	return nil
}

// printBanner prints the OWASPChecker banner
func (c *Commands) printBanner() {
	color.Cyan(`
╔══════════════════════════════════════════════════════════════╗
║                    OWASPChecker v1.0                        ║
║              OWASP Top 10 Security Scanner                   ║
║                                                              ║
║  🔍 Crawl • ⚔️ Attack • 📊 Report • 🛡️ Secure              ║
╚══════════════════════════════════════════════════════════════╝
`)
}

// isURL checks if the input is a valid URL
func (c *Commands) isURL(input string) bool {
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

// runCrawl executes the crawl operation
func (c *Commands) runCrawl(baseURL string, depth int) error {
	color.Yellow("🌐 Starting web crawler...")
	color.Yellow("   Target: %s", baseURL)
	color.Yellow("   Depth: %d", depth)

	crawler := crawl.NewCrawler(c.client, c.store)
	result, err := crawler.Crawl(baseURL, depth)
	if err != nil {
		return fmt.Errorf("crawl failed: %w", err)
	}

	duration := result.EndTime.Sub(result.StartTime)
	color.Green("✅ Crawl completed successfully!")
	color.Green("   📍 Base URL: %s", result.BaseURL)
	color.Green("   🔍 Depth: %d", result.Depth)
	color.Green("   📄 Requests discovered: %d", len(result.Requests))
	color.Green("   ⏱️  Duration: %v", duration)

	return nil
}

// runAttackURL executes attack directly on a URL
func (c *Commands) runAttackURL(targetURL string, concurrency int, delay int, burst int) error {
	color.Yellow("🌐 Creating request for URL: %s", targetURL)

	// Create a simple GET request for the URL
	request := common.RecordedRequest{
		ID:          uuid.New().String(),
		URL:         targetURL,
		Method:      "GET",
		Headers:     map[string]string{"User-Agent": "OWASPChecker/1.0"},
		Body:        "",
		ContentType: "",
		Variant:     "direct_url",
		Timestamp:   time.Now(),
		Source:      "direct_url",
	}

	requests := []common.RecordedRequest{request}
	color.Green("✅ Created request for direct URL attack")

	// Create attack engine
	engine := attack.NewEngine(c.client, c.store, concurrency, delay, burst)

	color.Yellow("⚔️ Starting direct URL attack...")
	color.Yellow("   🔥 Concurrency: %d", concurrency)
	color.Yellow("   📊 Target URL: %s", targetURL)

	// Create progress bar
	bar := progressbar.NewOptions(len(requests),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription("[cyan][1/1][reset] Attacking URL..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	result, err := engine.AttackWithProgress(requests, bar)
	if err != nil {
		return fmt.Errorf("attack failed: %w", err)
	}

	duration := result.EndTime.Sub(result.StartTime)
	color.Green("\n   📄 Original requests: %d", len(result.OriginalRequests))
	color.Green("   🔄 Mutated requests: %d", len(result.MutatedRequests))
	color.Green("   📡 Responses: %d", len(result.Responses))
	color.Green("   🚨 Findings: %d", len(result.Findings))
	color.Green("   ⏱️  Duration: %v", duration)

	// Store findings without progress bar to avoid conflicts
	if len(result.Findings) > 0 {
		color.Yellow("💾 Storing %d findings...", len(result.Findings))

		successCount := 0
		for _, finding := range result.Findings {
			if err := c.store.StoreFinding(&finding); err != nil {
				color.Red("❌ Failed to store finding: %v", err)
			} else {
				successCount++
			}
		}
		color.Green("✅ Successfully stored %d/%d findings", successCount, len(result.Findings))
	}

	return nil
}

// runAttackFromStore attacks requests from the database
func (c *Commands) runAttackFromStore(concurrency int, delay int, burst int) error {
	color.Yellow("📂 Loading requests from database...")

	// Get requests from store
	requests, err := c.store.GetRequests()
	if err != nil {
		return fmt.Errorf("failed to get requests from store: %w", err)
	}

	if len(requests) == 0 {
		color.Red("❌ No requests found in database. Run crawl first.")
		return nil
	}

	color.Green("✅ Loaded %d requests from database", len(requests))

	// Create attack engine
	engine := attack.NewEngine(c.client, c.store, concurrency, delay, burst)

	color.Yellow("⚔️ Starting security attack...")
	color.Yellow("   🔥 Concurrency: %d", concurrency)
	color.Yellow("   📊 Total requests to attack: %d", len(requests))

	// Create progress bar
	bar := progressbar.NewOptions(len(requests),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription("[cyan][1/1][reset] Attacking requests..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	result, err := engine.AttackWithProgress(requests, bar)
	if err != nil {
		return fmt.Errorf("attack failed: %w", err)
	}

	duration := result.EndTime.Sub(result.StartTime)
	color.Green("✅ Attack completed successfully!")
	color.Green("   📄 Original requests: %d", len(result.OriginalRequests))
	color.Green("   🔄 Mutated requests: %d", len(result.MutatedRequests))
	color.Green("   📡 Responses: %d", len(result.Responses))
	color.Green("   🚨 Findings: %d", len(result.Findings))
	color.Green("   ⏱️  Duration: %v", duration)

	// Store findings without progress bar to avoid conflicts
	if len(result.Findings) > 0 {
		color.Yellow("💾 Storing %d findings...", len(result.Findings))

		successCount := 0
		for _, finding := range result.Findings {
			if err := c.store.StoreFinding(&finding); err != nil {
				color.Red("❌ Failed to store finding: %v", err)
			} else {
				successCount++
			}
		}
		color.Green("✅ Successfully stored %d/%d findings", successCount, len(result.Findings))
	}

	return nil
}

// runAttack executes the attack operation
func (c *Commands) runAttack(requestsFile string, concurrency int, delay int, burst int) error {
	color.Yellow("📂 Loading requests from file...")

	// Load requests from file
	requests, err := c.loadRequests(requestsFile)
	if err != nil {
		return fmt.Errorf("failed to load requests: %w", err)
	}

	color.Green("✅ Loaded %d requests from file", len(requests))

	// Create attack engine
	engine := attack.NewEngine(c.client, c.store, concurrency, delay, burst)

	color.Yellow("⚔️ Starting security attack...")
	color.Yellow("   🔥 Concurrency: %d", concurrency)
	color.Yellow("   📊 Total requests to attack: %d", len(requests))

	// Create progress bar
	bar := progressbar.NewOptions(len(requests),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription("[cyan][1/1][reset] Attacking requests..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	result, err := engine.AttackWithProgress(requests, bar)
	if err != nil {
		return fmt.Errorf("attack failed: %w", err)
	}

	duration := result.EndTime.Sub(result.StartTime)
	color.Green("✅ Attack completed successfully!")
	color.Green("   📄 Original requests: %d", len(result.OriginalRequests))
	color.Green("   🔄 Mutated requests: %d", len(result.MutatedRequests))
	color.Green("   📡 Responses: %d", len(result.Responses))
	color.Green("   🚨 Findings: %d", len(result.Findings))
	color.Green("   ⏱️  Duration: %v", duration)

	// Store findings without progress bar to avoid conflicts
	if len(result.Findings) > 0 {
		color.Yellow("💾 Storing %d findings...", len(result.Findings))

		successCount := 0
		for _, finding := range result.Findings {
			if err := c.store.StoreFinding(&finding); err != nil {
				color.Red("❌ Failed to store finding: %v", err)
			} else {
				successCount++
			}
		}
		color.Green("✅ Successfully stored %d/%d findings", successCount, len(result.Findings))
	}

	return nil
}

// runReport generates the security report
func (c *Commands) runReport(outputFormat string) error {
	color.Yellow("📊 Generating %s report...", outputFormat)

	// Get findings from store
	findings, err := c.store.GetFindings()
	if err != nil {
		return fmt.Errorf("failed to get findings: %w", err)
	}

	if len(findings) == 0 {
		color.Yellow("⚠️  No findings to report.")
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

	color.Green("✅ Report generated: %s", outputFile)
	color.Green("   📊 Total findings: %d", len(findings))

	// Print summary with colors
	severityCounts := make(map[common.Severity]int)
	for _, finding := range findings {
		severityCounts[finding.Severity]++
	}

	// Print severity summary with colors
	for severity, count := range severityCounts {
		switch severity {
		case common.SeverityCritical:
			color.Red("   🚨 Critical: %d", count)
		case common.SeverityHigh:
			color.Magenta("   ⚠️  High: %d", count)
		case common.SeverityMedium:
			color.Yellow("   ⚡ Medium: %d", count)
		case common.SeverityLow:
			color.Blue("   ℹ️  Low: %d", count)
		}
	}

	// Print OWASP category summary
	color.Cyan("\n📊 OWASP Top 10 Categories:")
	categoryCounts := make(map[common.OWASPCategory]int)
	for _, finding := range findings {
		categoryCounts[finding.Category]++
	}

	// Sort categories by OWASP Top 10 order
	categoryOrder := []common.OWASPCategory{
		common.OWASPCategoryA01BrokenAccessControl,
		common.OWASPCategoryA02CryptographicFailures,
		common.OWASPCategoryA03Injection,
		common.OWASPCategoryA04InsecureDesign,
		common.OWASPCategoryA05SecurityMisconfiguration,
		common.OWASPCategoryA06VulnerableComponents,
		common.OWASPCategoryA07AuthFailures,
		common.OWASPCategoryA08SoftwareDataIntegrity,
		common.OWASPCategoryA09LoggingFailures,
		common.OWASPCategoryA10SSRF,
	}

	for _, category := range categoryOrder {
		if count, exists := categoryCounts[category]; exists && count > 0 {
			color.Yellow("   🔍 %s: %d", category, count)
		}
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
	case "html":
		return "html"
	case "json":
		return "json"
	default:
		return "html"
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
