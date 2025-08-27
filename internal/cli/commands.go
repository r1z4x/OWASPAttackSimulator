package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/owaspattacksimulator/internal/attack"
	"github.com/owaspattacksimulator/internal/common"
	"github.com/owaspattacksimulator/internal/crawl"
	"github.com/owaspattacksimulator/internal/har"
	"github.com/owaspattacksimulator/internal/httpx"
	"github.com/owaspattacksimulator/internal/report"
	"github.com/owaspattacksimulator/internal/store"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

// Commands represents CLI commands
type Commands struct {
	rootCmd *cobra.Command
	client  *httpx.Client
	store   *store.SQLiteStore
}

// setupCommands sets up all CLI commands
func (c *Commands) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:   "simulation [URL or requests-file]",
		Short: "OWASP Top 10 Web Application Security Scanner",
		Long: `OWASPAttackSimulator is a comprehensive web application security scanner 
that focuses on OWASP Top 10 vulnerabilities.

Usage:
  simulation <URL>                    # Attack a website directly
  simulation <requests-file>          # Attack requests from HAR/JSON file
  simulation --help                   # Show help

Examples:
  simulation https://example.com
  simulation requests.har
  simulation requests.json`,
		Args: cobra.MaximumNArgs(1),
		RunE: c.runMain,
	}

	// Add flags
	c.rootCmd.Flags().IntP("depth", "d", 3, "Maximum crawl depth (only for URL)")
	c.rootCmd.Flags().IntP("workers", "w", 10, "Number of worker threads")
	c.rootCmd.Flags().StringP("format", "f", "html", "Report format (html, json)")
	c.rootCmd.Flags().BoolP("crawl-only", "", false, "Only crawl, don't attack")
	c.rootCmd.Flags().BoolP("attack-only", "", false, "Only attack, don't crawl")
	c.rootCmd.Flags().Bool("clean", false, "Clean database before starting new scan")
	c.rootCmd.Flags().IntP("delay", "", 0, "Delay between requests in milliseconds (for rate limiting tests)")
	c.rootCmd.Flags().IntP("burst", "", 1, "Number of requests to send in burst before delay")
	c.rootCmd.Flags().BoolP("debug", "", false, "Enable debug mode to show request/response details")
}

// runMain handles the main command execution
func (c *Commands) runMain(cmd *cobra.Command, args []string) error {
	workers, _ := cmd.Flags().GetInt("workers")
	format, _ := cmd.Flags().GetString("format")
	clean, _ := cmd.Flags().GetBool("clean")
	delay, _ := cmd.Flags().GetInt("delay")
	burst, _ := cmd.Flags().GetInt("burst")
	debug, _ := cmd.Flags().GetBool("debug")

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals in a goroutine with immediate termination
	go func() {
		sig := <-sigChan
		color.Yellow("\n🛑 Received signal %v, terminating immediately...", sig)
		os.Exit(0)
	}()

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

		if err := c.runAttackURL(ctx, input, workers, delay, burst, debug); err != nil {
			if ctx.Err() == context.Canceled {
				color.Yellow("🛑 Attack cancelled by user")
				return nil
			}
			color.Red("❌ Attack failed: %v", err)
			return fmt.Errorf("attack failed: %w", err)
		}
	} else {
		// File provided - attack from file
		color.Cyan("🔍 Loading requests from file: %s", input)
		if delay > 0 {
			color.Yellow("⏱️ Delay between requests: %dms (burst: %d)", delay, burst)
		}

		if err := c.runAttack(ctx, input, workers, delay, burst, debug); err != nil {
			if ctx.Err() == context.Canceled {
				color.Yellow("🛑 Attack cancelled by user")
				return nil
			}
			color.Red("❌ Attack failed: %v", err)
			return fmt.Errorf("attack failed: %w", err)
		}
	}

	// Check if context was cancelled
	if ctx.Err() == context.Canceled {
		color.Yellow("🛑 Scan cancelled by user")
		return nil
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

// printBanner prints the OWASPAttackSimulator banner
func (c *Commands) printBanner() {
	color.Cyan(`
╔══════════════════════════════════════════════════════════════╗
║                OWASPAttackSimulator v1.0                     ║
║              OWASP Top 10 Security Scanner                   ║
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
func (c *Commands) runAttackURL(ctx context.Context, targetURL string, workers int, delay int, burst int, debug bool) error {
	color.Yellow("🌐 Creating request for URL: %s", targetURL)

	// Create a simple GET request for the URL
	request := common.RecordedRequest{
		ID:          uuid.New().String(),
		URL:         targetURL,
		Method:      "GET",
		Headers:     map[string]string{"User-Agent": "OWASPAttackSimulator/1.0"},
		Body:        "",
		ContentType: "",
		Variant:     "direct_url",
		Timestamp:   time.Now(),
		Source:      "direct_url",
	}

	requests := []common.RecordedRequest{request}
	color.Green("✅ Created request for direct URL attack")

	// Create attack engine
	engine := attack.NewEngine(c.client, c.store, workers, delay, burst)

	// Set debug mode if enabled
	if debug {
		color.Cyan("🐛 Debug mode enabled - showing request/response details")
		engine.SetDebugMode(true)
	}

	color.Yellow("⚔️ Starting direct URL attack...")
	color.Yellow("   🔥 Workers: %d", workers)
	color.Yellow("   📊 Target URL: %s", targetURL)

	// Create progress bar (only if not in debug mode)
	var bar *progressbar.ProgressBar
	if !debug {
		bar = progressbar.NewOptions(len(requests),
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
	}

	result, err := engine.AttackWithProgress(ctx, requests, bar)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return ctx.Err()
		}
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
func (c *Commands) runAttackFromStore(ctx context.Context, workers int, delay int, burst int) error {
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
	engine := attack.NewEngine(c.client, c.store, workers, delay, burst)

	color.Yellow("⚔️ Starting security attack...")
	color.Yellow("   🔥 Workers: %d", workers)
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

	result, err := engine.AttackWithProgress(ctx, requests, bar)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return ctx.Err()
		}
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
func (c *Commands) runAttack(ctx context.Context, requestsFile string, workers int, delay int, burst int, debug bool) error {
	color.Yellow("📂 Loading requests from file...")

	// Load requests from file
	requests, err := c.loadRequests(requestsFile)
	if err != nil {
		return fmt.Errorf("failed to load requests: %w", err)
	}

	color.Green("✅ Loaded %d requests from file", len(requests))

	// Create attack engine
	engine := attack.NewEngine(c.client, c.store, workers, delay, burst)

	// Set debug mode if enabled
	if debug {
		color.Cyan("🐛 Debug mode enabled - showing request/response details")
		engine.SetDebugMode(true)
	}

	color.Yellow("⚔️ Starting security attack...")
	color.Yellow("   🔥 Workers: %d", workers)
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

	result, err := engine.AttackWithProgress(ctx, requests, bar)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return ctx.Err()
		}
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
	outputFile := fmt.Sprintf("simulation_report.%s", getFileExtension(outputFormat))

	config := &common.ReportConfig{
		OutputFormat:    outputFormat,
		OutputFile:      outputFile,
		IncludeEvidence: true,
	}

	if err := reporter.GenerateReport(findings, config); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	color.Green("✅ Report generated: %s", outputFile)
	color.Green("   📊 Total findings: %d", len(findings))

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
