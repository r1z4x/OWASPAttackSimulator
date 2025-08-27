package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/owaspattacksimulator/internal/attack"
	"github.com/owaspattacksimulator/internal/common"
	"github.com/owaspattacksimulator/internal/report"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gopkg.in/yaml.v2"

	// Import the generated protobuf code
	proto "github.com/owaspattacksimulator"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AddAttackCommand adds the attack command directly to root
func AddAttackCommand(rootCmd *cobra.Command) {
	attackCmd := &cobra.Command{
		Use:   "attack",
		Short: "Run a direct attack",
		Long:  "Run a direct attack against a target URL with enhanced UI and automatic HTML report generation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			method, _ := cmd.Flags().GetString("method")
			payloadSet, _ := cmd.Flags().GetString("payload-set")
			workers, _ := cmd.Flags().GetInt("workers")
			timeoutStr, _ := cmd.Flags().GetString("timeout")
			generateReport, _ := cmd.Flags().GetBool("report")
			debug, _ := cmd.Flags().GetBool("debug")

			if target == "" {
				return fmt.Errorf("target URL is required")
			}

			// Parse timeout
			timeout, err := time.ParseDuration(timeoutStr)
			if err != nil {
				timeout = 30 * time.Second
			}

			// Create attack engine with enhanced UI
			attackEngine := attack.NewEngine(workers, timeout)

			// Set debug mode if enabled
			if debug {
				fmt.Println("🐛 Debug mode enabled - showing request/response details")
				attackEngine.SetDebugMode(true)
			}

			// Prepare attack configuration
			config := &attack.AttackConfig{
				Target:      target,
				Method:      method,
				PayloadSets: []string{payloadSet},
				Headers:     make(map[string]string),
			}

			// Run the attack
			result, err := attackEngine.RunAttack(config)
			if err != nil {
				return fmt.Errorf("attack failed: %v", err)
			}

			// Show enhanced results
			// showEnhancedResults(result) // This function is removed

			// Generate HTML report if requested
			if generateReport {
				fmt.Println("\n📊 Generating HTML report...")
				findings := convertAttackResultToFindings(result, target)
				reportFile := fmt.Sprintf("reports/attack_report_%s.html", time.Now().Format("20060102_150405"))

				// Use the existing reporter structure
				reporter := report.NewReporter()
				config := &common.ReportConfig{
					OutputFormat:    "html",
					OutputFile:      reportFile,
					IncludeEvidence: true,
				}

				err := reporter.GenerateReport(findings, config)
				if err != nil {
					fmt.Printf("❌ Failed to generate report: %v\n", err)
				} else {
					fmt.Printf("✅ HTML report generated: %s\n", reportFile)
				}
			}

			return nil
		},
	}

	attackCmd.Flags().String("target", "", "Target URL to attack")
	attackCmd.Flags().String("method", "GET", "HTTP method to use")
	attackCmd.Flags().String("payload-set", "all", "Payload set to use (default: all for comprehensive testing)")
	attackCmd.Flags().Int("workers", 3, "Number of worker threads")
	attackCmd.Flags().String("timeout", "30s", "Attack timeout")
	attackCmd.Flags().Bool("report", true, "Generate HTML report after attack")
	attackCmd.Flags().String("report-format", "html", "Report format (html, json, text)")
	attackCmd.Flags().Bool("debug", false, "Enable debug mode to show request/response details")
	attackCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(attackCmd)
}

// convertAttackResultToFindings converts attack result to findings format
func convertAttackResultToFindings(result *attack.AttackResult, target string) []common.Finding {
	// Debug: Print findings count
	fmt.Printf("🔍 Converting attack result to findings...\n")
	fmt.Printf("📊 Total findings found: %d\n", len(result.Findings))

	// Return the findings directly from the attack result
	// These are already in the correct format
	return result.Findings
}

// AddScenarioCommand adds the scenario command directly to root
func AddScenarioCommand(rootCmd *cobra.Command) {
	scenarioCmd := &cobra.Command{
		Use:   "scenario",
		Short: "Run a scenario file",
		Long:  "Execute a scenario from YAML file with automatic session management and enhanced UI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			file, _ := cmd.Flags().GetString("file")
			workers, _ := cmd.Flags().GetInt("workers")
			timeout, _ := cmd.Flags().GetString("timeout")
			delay, _ := cmd.Flags().GetInt("delay")
			debug, _ := cmd.Flags().GetBool("debug")

			if file == "" {
				return fmt.Errorf("scenario file is required")
			}

			// Create enhanced UI for scenario
			ui := attack.NewUI(true, true, false)

			ui.PrintBanner()
			ui.PrintInfo(fmt.Sprintf("🎬 Running scenario: %s", file))
			ui.PrintInfo(fmt.Sprintf("📊 Workers: %d", workers))
			ui.PrintInfo(fmt.Sprintf("⏱️  Timeout: %s", timeout))
			if delay > 0 {
				ui.PrintInfo(fmt.Sprintf("⏳ Delay: %dms between requests", delay))
			}

			// Parse scenario file
			scenario, err := parseScenarioFile(file)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Failed to parse scenario file: %v", err))
				return fmt.Errorf("failed to parse scenario file: %v", err)
			}

			ui.PrintInfo(fmt.Sprintf("📋 Scenario: %s", scenario.Name))
			ui.PrintInfo(fmt.Sprintf("📝 Description: %s", scenario.Description))

			// Use scenario workers if available, otherwise use command line workers
			scenarioWorkers := workers
			if scenario.Attack.Workers > 0 {
				scenarioWorkers = scenario.Attack.Workers
				ui.PrintInfo(fmt.Sprintf("📊 Using scenario workers: %d", scenarioWorkers))
			} else {
				ui.PrintInfo(fmt.Sprintf("📊 Using command line workers: %d", scenarioWorkers))
			}

			// Send scenario start to GUI
			ui.PrintInfo(fmt.Sprintf("🔍 Sending scenario start to GUI: %s", scenario.Name))
			go sendScenarioStartToGUI(scenario.Name, file)

			// Use scenario delay if available, otherwise use command line delay
			scenarioDelay := delay
			if scenario.Attack.Delay > 0 {
				scenarioDelay = scenario.Attack.Delay
				ui.PrintInfo(fmt.Sprintf("⏳ Using scenario delay: %dms", scenarioDelay))
			} else if delay > 0 {
				ui.PrintInfo(fmt.Sprintf("⏳ Using command line delay: %dms", scenarioDelay))
			}

			// Show debug mode status
			if debug {
				ui.PrintInfo("🐛 Debug mode enabled from command line")
			}

			// Execute scenario steps
			err = executeScenario(scenario, scenarioWorkers, timeout, scenarioDelay, debug)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Scenario execution failed: %v", err))
				return fmt.Errorf("scenario execution failed: %v", err)
			}

			ui.PrintSuccess("Scenario completed successfully")
			return nil
		},
	}

	scenarioCmd.Flags().String("file", "", "Scenario YAML file")
	scenarioCmd.Flags().Int("workers", 5, "Number of worker threads")
	scenarioCmd.Flags().String("timeout", "60s", "Scenario timeout")
	scenarioCmd.Flags().Int("delay", 0, "Delay in milliseconds between requests")
	scenarioCmd.Flags().Bool("debug", false, "Enable debug mode to show request/response details")
	scenarioCmd.MarkFlagRequired("file")

	rootCmd.AddCommand(scenarioCmd)
}

// AddReportCommand adds the report command to generate security reports
func AddReportCommand(rootCmd *cobra.Command) {
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate security report",
		Long:  "Generate detailed security reports from stored findings in various formats",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			outputFile, _ := cmd.Flags().GetString("output")
			includeEvidence, _ := cmd.Flags().GetBool("evidence")

			fmt.Printf("📊 Generating %s report...\n", format)

			// Create a summary finding for the report command
			summaryFinding := common.Finding{
				ID:             "report_summary_001",
				Type:           "Security Report",
				Category:       common.OWASPCategoryA01BrokenAccessControl,
				Title:          "Security report generated",
				Description:    "Security report generated using the report command",
				Evidence:       "Report generated successfully with available data",
				Payload:        "N/A",
				URL:            "Command-line report",
				Method:         "GET",
				ResponseStatus: 200,
				ResponseSize:   int64(1024),
				ResponseTime:   time.Duration(150 * time.Millisecond),
				Blocked:        false,
				RateLimited:    false,
				Timestamp:      time.Now(),
			}

			findings := []common.Finding{summaryFinding}

			if len(findings) == 0 {
				fmt.Println("⚠️  No findings to report.")
				return nil
			}

			// Use the proper reporter
			reporter := report.NewReporter()
			config := &common.ReportConfig{
				OutputFormat:    format,
				OutputFile:      outputFile,
				IncludeEvidence: includeEvidence,
			}

			return reporter.GenerateReport(findings, config)
		},
	}

	reportCmd.Flags().String("format", "html", "Report format (html, json, text)")
	reportCmd.Flags().String("output", "", "Output file (default: simulation_report.{format})")
	reportCmd.Flags().Bool("evidence", true, "Include evidence in report")

	rootCmd.AddCommand(reportCmd)
}

// Scenario structures
type Scenario struct {
	Version     string            `yaml:"version"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Vars        map[string]string `yaml:"vars"`
	Session     SessionConfig     `yaml:"session"`
	Attack      AttackConfig      `yaml:"attack"`
	Steps       []ScenarioStep    `yaml:"steps"`
	OnError     []ScenarioAction  `yaml:"on_error"`
	OnSuccess   []ScenarioAction  `yaml:"on_success"`
}

type SessionConfig struct {
	Enabled bool   `yaml:"enabled"`
	Target  string `yaml:"target"`
	Timeout string `yaml:"timeout"`
}

type AttackConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Workers     int      `yaml:"workers"`
	PayloadSets []string `yaml:"payload_sets"`
	Delay       int      `yaml:"delay"` // Delay in milliseconds between requests
	Debug       bool     `yaml:"debug"` // Debug mode flag
}

type ScenarioStep struct {
	ID              string              `yaml:"id"`
	Type            string              `yaml:"type"`
	URL             string              `yaml:"url"`
	Target          string              `yaml:"target"`
	Method          string              `yaml:"method"`
	Parameters      []string            `yaml:"parameters"`
	PayloadSets     []string            `yaml:"payload_sets"`
	Description     string              `yaml:"description"`
	Wait            string              `yaml:"wait"`
	Selectors       []map[string]string `yaml:"selectors"`
	Save            []string            `yaml:"save"`
	OnSuccess       []string            `yaml:"on_success"`
	OnFailure       []string            `yaml:"on_failure"`
	SessionRequired bool                `yaml:"session_required"`
}

type ScenarioAction struct {
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Format      string `yaml:"format"`
	Output      string `yaml:"output"`
}

// sendAttackStartToGUI sends attack start notification to GUI
func sendAttackStartToGUI(target, method, payloadSet string) {
	attackData := map[string]interface{}{
		"target":     target,
		"method":     method,
		"payloadSet": payloadSet,
		"startTime":  time.Now().Unix(),
		"status":     "running",
	}

	jsonData, err := json.Marshal(attackData)
	if err != nil {
		return
	}

	// Get GUI URL from environment or use default
	guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
	if guiURL == "" {
		guiURL = "http://localhost:3000"
	}

	// Create context with timeout for HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", guiURL+"/api/attack/start", strings.NewReader(string(jsonData)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Send to GUI API with context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// sendAttackUpdateToGUI sends attack progress update to GUI
func sendAttackUpdateToGUI(progress int, requests int, findings int, step string) {
	updateData := map[string]interface{}{
		"progress":   progress,
		"requests":   requests,
		"findings":   findings,
		"step":       step,
		"lastUpdate": time.Now().Unix(),
	}

	jsonData, err := json.Marshal(updateData)
	if err != nil {
		return
	}

	// Get GUI URL from environment or use default
	guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
	if guiURL == "" {
		guiURL = "http://localhost:3000"
	}

	// Create context with timeout for HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", guiURL+"/api/attack/update", strings.NewReader(string(jsonData)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Send to GUI API with context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// parseScenarioFile parses a YAML scenario file
func parseScenarioFile(filepath string) (*Scenario, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var scenario Scenario
	err = yaml.Unmarshal(data, &scenario)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}

	return &scenario, nil
}

// sendScenarioStartToGUI sends scenario start notification to GUI
func sendScenarioStartToGUI(scenarioName, file string) {
	scenarioData := map[string]interface{}{
		"scenario":  scenarioName,
		"file":      file,
		"startTime": time.Now().Unix(),
		"status":    "running",
	}

	jsonData, err := json.Marshal(scenarioData)
	if err != nil {
		fmt.Printf("❌ Failed to marshal scenario data: %v\n", err)
		return
	}

	fmt.Printf("🔍 Sending to GUI: %s\n", string(jsonData))

	// Get GUI URL from environment or use default
	guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
	if guiURL == "" {
		guiURL = "http://localhost:3000"
	}

	// Create context with timeout for HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", guiURL+"/api/attack/start", strings.NewReader(string(jsonData)))
	if err != nil {
		fmt.Printf("❌ Failed to create request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Send to GUI API with context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ Failed to send to GUI: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("✅ Scenario start sent to GUI successfully\n")
}

// sendScenarioErrorToGUI sends scenario error notification to GUI
func sendScenarioErrorToGUI(scenarioName string, errorMessage string, totalRequests int, totalFindings int) {
	errorData := map[string]interface{}{
		"scenario":   scenarioName,
		"progress":   0,
		"requests":   totalRequests,
		"findings":   totalFindings,
		"step":       errorMessage,
		"status":     "failed",
		"lastUpdate": time.Now().Unix(),
	}

	jsonData, err := json.Marshal(errorData)
	if err != nil {
		fmt.Printf("❌ Failed to marshal error data: %v\n", err)
		return
	}

	// Get GUI URL from environment or use default
	guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
	if guiURL == "" {
		guiURL = "http://localhost:3000"
	}

	// Send to GUI API
	resp, err := http.Post(guiURL+"/api/attack/update", "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		fmt.Printf("❌ Failed to send error to GUI: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("✅ Error status sent to GUI: %s\n", errorMessage)
}

// sendScenarioCompletionToGUI sends scenario completion notification to GUI
func sendScenarioCompletionToGUI(scenarioName string, totalRequests int, totalFindings int) {
	completionData := map[string]interface{}{
		"scenario":   scenarioName,
		"progress":   100,
		"requests":   totalRequests,
		"findings":   totalFindings,
		"step":       "Scenario completed successfully",
		"status":     "completed",
		"lastUpdate": time.Now().Unix(),
	}

	jsonData, err := json.Marshal(completionData)
	if err != nil {
		fmt.Printf("❌ Failed to marshal completion data: %v\n", err)
		return
	}

	fmt.Printf("🔍 Sending completion to GUI: %s\n", string(jsonData))

	// Get GUI URL from environment or use default
	guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
	if guiURL == "" {
		guiURL = "http://localhost:3000"
	}

	// Create context with timeout for HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", guiURL+"/api/attack/update", strings.NewReader(string(jsonData)))
	if err != nil {
		fmt.Printf("❌ Failed to create request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Send to GUI API with context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ Failed to send completion to GUI: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("✅ Scenario completion sent to GUI successfully\n")
}

// executeStepWithRetry executes a step with retry mechanism
func executeStepWithRetry(ctx context.Context, step ScenarioStep, stepIndex int, totalSteps int, attackEngine *attack.Engine, scenario *Scenario, totalRequests *int, totalFindings *int, delay int) error {
	maxRetries := 3
	retryDelay := 500 * time.Millisecond // Reduced from 2 seconds to 500ms

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Check for context cancellation before each attempt
		select {
		case <-ctx.Done():
			return fmt.Errorf("step cancelled: %v", ctx.Err())
		default:
			// Continue with step execution
		}

		fmt.Printf("📋 Step %d/%d: %s (%s) - Attempt %d/%d\n", stepIndex+1, totalSteps, step.ID, step.Type, attempt, maxRetries)

		// Send step progress to GUI
		progress := (stepIndex * 100) / totalSteps
		sendAttackUpdateToGUI(progress, *totalRequests, *totalFindings, fmt.Sprintf("Executing: %s (Attempt %d/%d)", step.Description, attempt, maxRetries))

		var err error
		var requests, findings int

		// Execute step based on type
		switch step.Type {
		case "net:attack":
			requests, findings, err = executeAttackStep(ctx, step, attackEngine, scenario, delay)
			if err == nil {
				*totalRequests += requests
				*totalFindings += findings
			}
		case "browser:navigate":
			err = executeNavigateStep(step, scenario)
		case "browser:fill":
			err = executeFillStep(step, scenario)
		case "browser:click":
			err = executeClickStep(step, scenario)
		default:
			fmt.Printf("⚠️  Unknown step type: %s\n", step.Type)
			return nil // Skip unknown steps
		}

		if err == nil {
			fmt.Printf("✅ Step completed: %s\n", step.Description)
			return nil
		}

		fmt.Printf("❌ Step failed (Attempt %d/%d): %v\n", attempt, maxRetries, err)

		if attempt < maxRetries {
			fmt.Printf("🔄 Retrying in %v...\n", retryDelay)
			time.Sleep(retryDelay)
			retryDelay = time.Duration(float64(retryDelay) * 1.5) // Reduced exponential backoff from 2x to 1.5x
		} else {
			return fmt.Errorf("step '%s' failed after %d attempts: %v", step.Description, maxRetries, err)
		}
	}

	return fmt.Errorf("unexpected error in retry loop")
}

// executeScenario executes all steps in a scenario
func executeScenario(scenario *Scenario, workers int, timeout string, delay int, debug bool) error {
	// Check if debug mode is enabled in scenario or command line
	scenarioDebug := scenario.Attack.Debug
	debugEnabled := debug || scenarioDebug
	if debugEnabled {
		if debug {
			fmt.Printf("🐛 Debug mode enabled from command line\n")
		}
		if scenarioDebug {
			fmt.Printf("🐛 Debug mode enabled from scenario configuration\n")
		}
	}
	fmt.Printf("🚀 Executing scenario with %d steps\n", len(scenario.Steps))

	// Parse timeout
	timeoutDuration, err := time.ParseDuration(timeout)
	if err != nil {
		timeoutDuration = 60 * time.Second
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Handle signals in a goroutine with immediate termination
	go func() {
		sig := <-sigChan
		fmt.Printf("\n🛑 Received signal %v, terminating immediately...\n", sig)
		os.Exit(0)
	}()

	// Create attack engine
	attackEngine := attack.NewEngine(workers, timeoutDuration)

	// Set debug mode if enabled in scenario or command line
	if debugEnabled {
		attackEngine.SetDebugMode(true)
	}

	// Track total metrics
	totalRequests := 0
	totalFindings := 0

	// Execute each step with retry mechanism
	for i, step := range scenario.Steps {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			errorMessage := "Scenario cancelled"
			if ctx.Err() == context.Canceled {
				errorMessage = "Scenario cancelled by user"
			} else {
				errorMessage = "Scenario cancelled due to timeout"
			}
			sendScenarioErrorToGUI(scenario.Name, errorMessage, totalRequests, totalFindings)
			return fmt.Errorf("scenario cancelled: %v", ctx.Err())
		default:
			// Continue with step execution
		}

		err := executeStepWithRetry(ctx, step, i, len(scenario.Steps), attackEngine, scenario, &totalRequests, &totalFindings, delay)
		if err != nil {
			// Send error status to GUI
			errorMessage := fmt.Sprintf("Failed at step %d: %s", i+1, step.Description)
			sendScenarioErrorToGUI(scenario.Name, errorMessage, totalRequests, totalFindings)
			return fmt.Errorf("scenario failed at step %d (%s): %v", i+1, step.Description, err)
		}
	}

	// Send final completion to GUI with total metrics
	sendScenarioCompletionToGUI(scenario.Name, totalRequests, totalFindings)

	// Execute on_success actions
	if len(scenario.OnSuccess) > 0 {
		fmt.Printf("🎉 Executing on_success actions...\n")
		for _, action := range scenario.OnSuccess {
			err := executeScenarioAction(action, scenario, totalRequests, totalFindings)
			if err != nil {
				fmt.Printf("⚠️  Warning: Failed to execute on_success action: %v\n", err)
			}
		}
	}

	return nil
}

// executeAttackStep executes a net:attack step
func executeAttackStep(ctx context.Context, step ScenarioStep, attackEngine *attack.Engine, scenario *Scenario, delay int) (int, int, error) {
	fmt.Printf("🎯 Executing attack: %s\n", step.Description)

	// Get URL from either URL or Target field
	urlToResolve := step.URL
	if urlToResolve == "" {
		urlToResolve = step.Target
	}

	// Debug: Print original URL and variables
	fmt.Printf("🔍 Original URL: %s\n", urlToResolve)
	fmt.Printf("🔍 Variables: %+v\n", scenario.Vars)

	// Resolve variables in URL
	resolvedURL := resolveVariables(urlToResolve, scenario.Vars)
	fmt.Printf("🔍 Resolved URL: %s\n", resolvedURL)

	if resolvedURL == "" {
		return 0, 0, fmt.Errorf("empty URL after variable resolution")
	}

	// Set default method if not specified
	method := step.Method
	if method == "" {
		method = "GET"
	}

	// Prepare attack configuration
	config := &attack.AttackConfig{
		Target:      resolvedURL,
		Method:      method,
		PayloadSets: step.PayloadSets,
		Parameters:  step.Parameters, // Use parameters from scenario step
		Headers:     make(map[string]string),
	}

	// Run the attack
	result, err := attackEngine.RunAttack(config)
	if err != nil {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return 0, 0, fmt.Errorf("attack cancelled: %v", ctx.Err())
		default:
			return 0, 0, fmt.Errorf("attack failed: %v", err)
		}
	}

	fmt.Printf("✅ Attack completed: %d requests, %d vulnerabilities\n", result.TotalRequests, len(result.Vulnerabilities))
	return result.TotalRequests, len(result.Vulnerabilities), nil
}

// executeScenarioAction executes a scenario action (like report generation)
func executeScenarioAction(action ScenarioAction, scenario *Scenario, totalRequests int, totalFindings int) error {
	switch action.Type {
	case "report:generate":
		return executeReportGeneration(action, scenario, totalRequests, totalFindings)
	default:
		return fmt.Errorf("unsupported action type: %s", action.Type)
	}
}

// executeReportGeneration handles report generation actions
func executeReportGeneration(action ScenarioAction, scenario *Scenario, totalRequests int, totalFindings int) error {
	format := "html" // default format
	if action.Format != "" {
		format = action.Format
	}

	outputFile := action.Output
	if outputFile == "" {
		outputFile = fmt.Sprintf("reports/%s_results.%s", strings.ToLower(strings.ReplaceAll(scenario.Name, " ", "_")), format)
	}

	fmt.Printf("📊 Generating %s report: %s\n", format, outputFile)

	// Only create findings if there are actual vulnerabilities or significant results
	var findings []common.Finding

	if totalFindings > 0 {
		// Create findings for actual vulnerabilities
		fmt.Printf("📊 Found %d vulnerabilities to report\n", totalFindings)
		// TODO: Add real vulnerability findings here
	} else if totalRequests > 0 {
		// No vulnerabilities found, but scan completed successfully
		fmt.Printf("✅ Scan completed: %d requests tested, no vulnerabilities found\n", totalRequests)
		// Don't create any findings for clean scans - only report if vulnerabilities exist
		return nil
	} else {
		// No attack data available
		fmt.Printf("⚠️  No attack data available for report generation\n")
		return nil
	}

	// Use the proper reporter
	reporter := report.NewReporter()
	config := &common.ReportConfig{
		OutputFormat:    format,
		OutputFile:      outputFile,
		IncludeEvidence: true,
	}

	return reporter.GenerateReport(findings, config)
}

// executeNavigateStep executes a browser:navigate step
func executeNavigateStep(step ScenarioStep, scenario *Scenario) error {
	fmt.Printf("🌐 Navigating to: %s\n", step.URL)

	// Resolve URL variables
	resolvedURL := resolveVariables(step.URL, scenario.Vars)
	if resolvedURL == "" {
		return fmt.Errorf("empty URL after variable resolution")
	}

	fmt.Printf("🔍 Resolved URL: %s\n", resolvedURL)
	fmt.Printf("🔍 Wait parameter: %s\n", step.Wait)

	// Send navigation command to GUI
	navigationData := map[string]interface{}{
		"action": "navigate",
		"url":    resolvedURL,
		"wait":   step.Wait,
		"step":   step.Description,
	}

	jsonData, err := json.Marshal(navigationData)
	if err != nil {
		return fmt.Errorf("failed to marshal navigation data: %v", err)
	}

	// Get GUI URL from environment or use default
	guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
	if guiURL == "" {
		guiURL = "http://localhost:3000"
	}

	// Create context with timeout for HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "POST", guiURL+"/api/browser/action", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send to GUI API with context
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send navigation command: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("navigation command failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to check if action was successful
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		if errorMsg, ok := response["error"].(string); ok {
			return fmt.Errorf("navigation action failed: %s", errorMsg)
		}
		return fmt.Errorf("navigation action failed: unknown error")
	}

	fmt.Printf("✅ Navigation command completed: %s\n", resolvedURL)
	return nil
}

// executeFillStep executes a browser:fill step
func executeFillStep(step ScenarioStep, scenario *Scenario) error {
	fmt.Printf("📝 Filling form: %s\n", step.Description)

	// Process selectors and values
	for _, selector := range step.Selectors {
		selectorStr := selector["sel"]
		value := resolveVariables(selector["value"], scenario.Vars)

		// Send fill command to GUI
		fillData := map[string]interface{}{
			"action":   "fill",
			"selector": selectorStr,
			"value":    value,
			"step":     step.Description,
		}

		jsonData, err := json.Marshal(fillData)
		if err != nil {
			return fmt.Errorf("failed to marshal fill data: %v", err)
		}

		// Get GUI URL from environment or use default
		guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
		if guiURL == "" {
			guiURL = "http://localhost:3000"
		}

		// Create context with timeout for HTTP request
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create HTTP request with context
		req, err := http.NewRequestWithContext(ctx, "POST", guiURL+"/api/browser/action", strings.NewReader(string(jsonData)))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		// Send to GUI API with context
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send fill command: %v", err)
		}
		defer resp.Body.Close()

		// Check response status
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("fill command failed with status %d: %s", resp.StatusCode, string(body))
		}

		// Parse response to check if action was successful
		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		if success, ok := response["success"].(bool); !ok || !success {
			if errorMsg, ok := response["error"].(string); ok {
				return fmt.Errorf("fill action failed: %s", errorMsg)
			}
			return fmt.Errorf("fill action failed: unknown error")
		}

		fmt.Printf("✅ Fill command completed: %s = %s\n", selectorStr, value)
	}

	return nil
}

// executeClickStep executes a browser:click step
func executeClickStep(step ScenarioStep, scenario *Scenario) error {
	fmt.Printf("🖱️  Clicking: %s\n", step.Description)

	// Process selectors
	for _, selector := range step.Selectors {
		selectorStr := selector["sel"]

		// Send click command to GUI
		clickData := map[string]interface{}{
			"action":   "click",
			"selector": selectorStr,
			"step":     step.Description,
		}

		jsonData, err := json.Marshal(clickData)
		if err != nil {
			return fmt.Errorf("failed to marshal click data: %v", err)
		}

		// Get GUI URL from environment or use default
		guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
		if guiURL == "" {
			guiURL = "http://localhost:3000"
		}

		// Create context with timeout for HTTP request
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create HTTP request with context
		req, err := http.NewRequestWithContext(ctx, "POST", guiURL+"/api/browser/action", strings.NewReader(string(jsonData)))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		// Send to GUI API with context
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send click command: %v", err)
		}
		defer resp.Body.Close()

		// Check response status
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("click command failed with status %d: %s", resp.StatusCode, string(body))
		}

		// Parse response to check if action was successful
		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		if success, ok := response["success"].(bool); !ok || !success {
			if errorMsg, ok := response["error"].(string); ok {
				return fmt.Errorf("click action failed: %s", errorMsg)
			}
			return fmt.Errorf("click action failed: unknown error")
		}

		fmt.Printf("✅ Click command completed: %s\n", selectorStr)
	}

	return nil
}

// resolveVariables resolves {{ vars.* }} variables in strings
func resolveVariables(input string, vars map[string]string) string {
	result := input

	// Replace {{ vars.variable_name }} with actual values
	for key, value := range vars {
		placeholder := fmt.Sprintf("{{ vars.%s }}", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result
}

// AddServerCommand adds the server command to run gRPC server
func AddServerCommand(rootCmd *cobra.Command) {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run gRPC server",
		Long:  "Run the gRPC broker server for OWASP Attack Simulator",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			port, _ := cmd.Flags().GetString("port")
			if port == "" {
				port = "50051"
			}

			fmt.Printf("🚀 Starting gRPC server on port %s...\n", port)

			// Create gRPC server
			grpcServer := grpc.NewServer()

			// Register services
			proto.RegisterSessionServiceServer(grpcServer, &SessionServer{})
			proto.RegisterStepServiceServer(grpcServer, &StepServer{})
			proto.RegisterArtifactServiceServer(grpcServer, &ArtifactServer{})

			// Enable reflection for debugging
			reflection.Register(grpcServer)

			// Create listener
			lis, err := net.Listen("tcp", ":"+port)
			if err != nil {
				return fmt.Errorf("failed to listen: %v", err)
			}

			fmt.Printf("✅ gRPC server listening on port %s\n", port)

			// Start server in goroutine
			go func() {
				if err := grpcServer.Serve(lis); err != nil {
					fmt.Printf("❌ Failed to serve: %v\n", err)
				}
			}()

			// Wait for interrupt signal
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan

			fmt.Println("🛑 Shutting down gRPC server...")
			grpcServer.GracefulStop()

			return nil
		},
	}

	serverCmd.Flags().String("port", "50051", "Port to run the gRPC server on")
	rootCmd.AddCommand(serverCmd)
}

// SessionServer implements the SessionService
type SessionServer struct {
	proto.UnimplementedSessionServiceServer
}

func (s *SessionServer) OpenSession(ctx context.Context, req *proto.OpenSessionRequest) (*proto.OpenSessionResponse, error) {
	fmt.Printf("📝 Opening session for target: %s\n", req.TargetUrl)

	// Generate session ID
	sessionID := fmt.Sprintf("session_%d", time.Now().Unix())

	return &proto.OpenSessionResponse{
		SessionId: sessionID,
		SessionInfo: &proto.SessionInfo{
			SessionId: sessionID,
			TargetUrl: req.TargetUrl,
			CreatedAt: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
			UpdatedAt: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
		},
	}, nil
}

func (s *SessionServer) AttachSession(ctx context.Context, req *proto.AttachSessionRequest) (*proto.AttachSessionResponse, error) {
	fmt.Printf("🔗 Attaching to session: %s\n", req.SessionId)

	return &proto.AttachSessionResponse{
		SessionInfo: &proto.SessionInfo{
			SessionId: req.SessionId,
			CreatedAt: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
			UpdatedAt: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
		},
	}, nil
}

func (s *SessionServer) DetachSession(ctx context.Context, req *proto.DetachSessionRequest) (*proto.DetachSessionResponse, error) {
	fmt.Printf("🔌 Detaching from session: %s\n", req.SessionId)
	return &proto.DetachSessionResponse{Success: true}, nil
}

func (s *SessionServer) CloseSession(ctx context.Context, req *proto.CloseSessionRequest) (*proto.CloseSessionResponse, error) {
	fmt.Printf("❌ Closing session: %s\n", req.SessionId)
	return &proto.CloseSessionResponse{Success: true}, nil
}

func (s *SessionServer) GetSession(ctx context.Context, req *proto.GetSessionRequest) (*proto.GetSessionResponse, error) {
	fmt.Printf("📋 Getting session: %s\n", req.SessionId)

	return &proto.GetSessionResponse{
		SessionInfo: &proto.SessionInfo{
			SessionId: req.SessionId,
			CreatedAt: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
			UpdatedAt: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
		},
	}, nil
}

func (s *SessionServer) UpdateSession(ctx context.Context, req *proto.UpdateSessionRequest) (*proto.UpdateSessionResponse, error) {
	fmt.Printf("🔄 Updating session: %s\n", req.SessionId)
	return &proto.UpdateSessionResponse{Success: true}, nil
}

// StepServer implements the StepService
type StepServer struct {
	proto.UnimplementedStepServiceServer
}

func (s *StepServer) PushStep(ctx context.Context, req *proto.PushStepRequest) (*proto.PushStepResponse, error) {
	fmt.Printf("📤 Pushing step %s for session %s\n", req.Step.Id, req.SessionId)

	stepID := fmt.Sprintf("step_%d", time.Now().Unix())
	return &proto.PushStepResponse{
		StepId: stepID,
		Queued: true,
	}, nil
}

func (s *StepServer) CancelStep(ctx context.Context, req *proto.CancelStepRequest) (*proto.CancelStepResponse, error) {
	fmt.Printf("❌ Cancelling step %s for session %s\n", req.StepId, req.SessionId)
	return &proto.CancelStepResponse{Cancelled: true}, nil
}

func (s *StepServer) GetStepStatus(ctx context.Context, req *proto.GetStepStatusRequest) (*proto.GetStepStatusResponse, error) {
	fmt.Printf("📊 Getting status for step %s in session %s\n", req.StepId, req.SessionId)

	return &proto.GetStepStatusResponse{
		Status: &proto.StepStatus{
			StepId:      req.StepId,
			Status:      "COMPLETED",
			StartedAt:   &timestamppb.Timestamp{Seconds: time.Now().Unix() - 10},
			CompletedAt: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
		},
	}, nil
}

func (s *StepServer) StreamEvents(req *proto.StreamEventsRequest, stream proto.StepService_StreamEventsServer) error {
	fmt.Printf("📡 Starting event stream for session %s\n", req.SessionId)

	// Send a few sample events
	for i := 0; i < 3; i++ {
		event := &proto.Event{
			EventId:   fmt.Sprintf("event_%d", i),
			SessionId: req.SessionId,
			Kind:      "STEP_STARTED",
			Timestamp: &timestamppb.Timestamp{Seconds: time.Now().Unix()},
		}

		if err := stream.Send(event); err != nil {
			return err
		}

		time.Sleep(1 * time.Second)
	}

	return nil
}

// ArtifactServer implements the ArtifactService
type ArtifactServer struct {
	proto.UnimplementedArtifactServiceServer
}

func (s *ArtifactServer) PushArtifact(ctx context.Context, req *proto.PushArtifactRequest) (*proto.PushArtifactResponse, error) {
	fmt.Printf("💾 Pushing artifact %s for step %s\n", req.Kind, req.StepId)
	return &proto.PushArtifactResponse{Saved: true}, nil
}

func (s *ArtifactServer) GetArtifact(ctx context.Context, req *proto.GetArtifactRequest) (*proto.GetArtifactResponse, error) {
	fmt.Printf("📥 Getting artifact %s\n", req.ArtifactId)
	return &proto.GetArtifactResponse{
		Data: []byte("sample artifact data"),
	}, nil
}

func (s *ArtifactServer) ListArtifacts(ctx context.Context, req *proto.ListArtifactsRequest) (*proto.ListArtifactsResponse, error) {
	fmt.Printf("📋 Listing artifacts for session %s\n", req.SessionId)
	return &proto.ListArtifactsResponse{
		Artifacts: []*proto.ArtifactInfo{
			{
				ArtifactId: "artifact_1",
				SessionId:  req.SessionId,
				Kind:       "screenshot",
				Path:       "/data/screenshots/screen1.png",
			},
		},
	}, nil
}
