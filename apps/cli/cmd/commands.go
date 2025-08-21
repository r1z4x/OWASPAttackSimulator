package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/owaspchecker/pkg/engine"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// AddAttackCommand adds the attack command directly to root
func AddAttackCommand(rootCmd *cobra.Command) {
	attackCmd := &cobra.Command{
		Use:   "attack",
		Short: "Run a direct attack",
		Long:  "Run a direct attack against a target URL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _ := cmd.Flags().GetString("target")
			method, _ := cmd.Flags().GetString("method")
			payload, _ := cmd.Flags().GetString("payload")
			payloadSet, _ := cmd.Flags().GetString("payload-set")
			concurrency, _ := cmd.Flags().GetInt("concurrency")
			timeoutStr, _ := cmd.Flags().GetString("timeout")
			noGui, _ := cmd.Flags().GetBool("no-gui")

			if target == "" {
				return fmt.Errorf("target URL is required")
			}

			// Parse timeout
			timeout, err := time.ParseDuration(timeoutStr)
			if err != nil {
				timeout = 30 * time.Second
			}

			fmt.Printf("🚀 Starting attack against: %s\n", target)
			fmt.Printf("📊 Method: %s\n", method)
			fmt.Printf("📊 Concurrency: %d\n", concurrency)
			fmt.Printf("⏱️  Timeout: %s\n", timeout)

			if payload != "" {
				fmt.Printf("📊 Custom payload: %s\n", payload)
			} else {
				fmt.Printf("📊 Payload set: %s\n", payloadSet)
			}

			// Send attack start notification to GUI
			if !noGui {
				go sendAttackStartToGUI(target, method, payloadSet)
			}

			// Create attack engine
			attackEngine := engine.NewEngine(timeout, concurrency)

			// Prepare attack configuration
			config := &engine.AttackConfig{
				Target:      target,
				Method:      method,
				PayloadSets: []string{payloadSet},
				Headers:     make(map[string]string),
			}

			// Add custom payload if provided
			if payload != "" {
				// Create custom payload set
				customSet := engine.PayloadSet{
					Name:     "Custom",
					Type:     "custom",
					Payloads: []string{payload},
				}
				attackEngine.AddPayloadSet("custom", customSet)
				config.PayloadSets = []string{"custom"}
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// Start progress tracking goroutine
			if !noGui {
				go func() {
					ticker := time.NewTicker(2 * time.Second)
					defer ticker.Stop()

					progress := 0
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							progress += 10
							if progress > 90 {
								progress = 90
							}
							sendAttackUpdateToGUI(progress, 0, 0, "Running attack...")
						}
					}
				}()
			}

			// Run the attack
			result, err := attackEngine.RunAttack(ctx, config)
			if err != nil {
				return fmt.Errorf("attack failed: %v", err)
			}

			// Send final update to GUI
			if !noGui {
				sendAttackUpdateToGUI(100, result.TotalRequests, len(result.Vulnerabilities), "Attack completed")
			}

			// Display results
			fmt.Println("✅ Attack completed successfully")
			fmt.Printf("📊 Results:\n")
			fmt.Printf("  - Total requests: %d\n", result.TotalRequests)
			fmt.Printf("  - Vulnerabilities found: %d\n", len(result.Vulnerabilities))
			fmt.Printf("  - Duration: %s\n", result.Duration)

			// Show detailed vulnerabilities
			for i, vuln := range result.Vulnerabilities {
				fmt.Printf("  %d. %s in parameter '%s'\n", i+1, vuln.Type, vuln.Parameter)
				fmt.Printf("     Evidence: %s\n", vuln.Evidence)
				fmt.Printf("     Confidence: %.1f%%\n", vuln.Confidence*100)
			}

			if !noGui {
				guiURL := os.Getenv("OWASPCHECKER_GUI_URL")
				if guiURL == "" {
					guiURL = "http://localhost:3000"
				}
				fmt.Printf("📈 Check %s for detailed results\n", guiURL)
			}

			return nil
		},
	}

	attackCmd.Flags().String("target", "", "Target URL to attack")
	attackCmd.Flags().String("method", "GET", "HTTP method to use")
	attackCmd.Flags().String("payload", "", "Custom payload to inject")
	attackCmd.Flags().String("payload-set", "xss.reflected", "Payload set to use")
	attackCmd.Flags().Int("concurrency", 3, "Number of concurrent workers")
	attackCmd.Flags().String("timeout", "30s", "Attack timeout")
	attackCmd.Flags().Bool("no-gui", false, "Disable GUI updates")
	attackCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(attackCmd)
}

// AddQuickCommand adds the quick command directly to root (removed)
func AddQuickCommand(rootCmd *cobra.Command) {
	// Quick command removed - use attack command instead
}

// AddScenarioCommand adds the scenario command directly to root
func AddScenarioCommand(rootCmd *cobra.Command) {
	scenarioCmd := &cobra.Command{
		Use:   "scenario",
		Short: "Run a scenario file",
		Long:  "Execute a scenario from YAML file with automatic session management",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			file, _ := cmd.Flags().GetString("file")
			concurrency, _ := cmd.Flags().GetInt("concurrency")
			timeout, _ := cmd.Flags().GetString("timeout")

			if file == "" {
				return fmt.Errorf("scenario file is required")
			}

			fmt.Printf("🎬 Running scenario: %s\n", file)
			fmt.Printf("📊 Concurrency: %d\n", concurrency)
			fmt.Printf("⏱️  Timeout: %s\n", timeout)

			// Parse scenario file
			scenario, err := parseScenarioFile(file)
			if err != nil {
				return fmt.Errorf("failed to parse scenario file: %v", err)
			}

			fmt.Printf("📋 Scenario: %s\n", scenario.Name)
			fmt.Printf("📝 Description: %s\n", scenario.Description)

			// Send scenario start to GUI
			fmt.Printf("🔍 Sending scenario start to GUI: %s\n", scenario.Name)
			go sendScenarioStartToGUI(scenario.Name, file)

			// Execute scenario steps
			err = executeScenario(scenario, concurrency, timeout)
			if err != nil {
				return fmt.Errorf("scenario execution failed: %v", err)
			}

			fmt.Println("✅ Scenario completed successfully")
			return nil
		},
	}

	scenarioCmd.Flags().String("file", "", "Scenario YAML file")
	scenarioCmd.Flags().Int("concurrency", 5, "Number of concurrent workers")
	scenarioCmd.Flags().String("timeout", "60s", "Scenario timeout")
	scenarioCmd.MarkFlagRequired("file")

	rootCmd.AddCommand(scenarioCmd)
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
	Concurrency int      `yaml:"concurrency"`
	PayloadSets []string `yaml:"payload_sets"`
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
func executeStepWithRetry(step ScenarioStep, stepIndex int, totalSteps int, attackEngine *engine.Engine, scenario *Scenario, totalRequests *int, totalFindings *int) error {
	maxRetries := 3
	retryDelay := 500 * time.Millisecond // Reduced from 2 seconds to 500ms

	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("📋 Step %d/%d: %s (%s) - Attempt %d/%d\n", stepIndex+1, totalSteps, step.ID, step.Type, attempt, maxRetries)

		// Send step progress to GUI
		progress := (stepIndex * 100) / totalSteps
		sendAttackUpdateToGUI(progress, *totalRequests, *totalFindings, fmt.Sprintf("Executing: %s (Attempt %d/%d)", step.Description, attempt, maxRetries))

		var err error
		var requests, findings int

		// Execute step based on type
		switch step.Type {
		case "net:attack":
			requests, findings, err = executeAttackStep(step, attackEngine, scenario)
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
		case "session:capture":
			err = executeCaptureStep(step, scenario)
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
func executeScenario(scenario *Scenario, concurrency int, timeout string) error {
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

	// Create attack engine
	attackEngine := engine.NewEngine(timeoutDuration, concurrency)

	// Track total metrics
	totalRequests := 0
	totalFindings := 0

	// Execute each step with retry mechanism
	for i, step := range scenario.Steps {
		// Check for context cancellation or signals
		select {
		case <-ctx.Done():
			errorMessage := "Scenario cancelled due to timeout"
			sendScenarioErrorToGUI(scenario.Name, errorMessage, totalRequests, totalFindings)
			return fmt.Errorf("scenario cancelled: %v", ctx.Err())
		case sig := <-sigChan:
			errorMessage := fmt.Sprintf("Scenario interrupted by signal: %v", sig)
			sendScenarioErrorToGUI(scenario.Name, errorMessage, totalRequests, totalFindings)
			return fmt.Errorf("scenario interrupted: %v", sig)
		default:
			// Continue with step execution
		}

		err := executeStepWithRetry(step, i, len(scenario.Steps), attackEngine, scenario, &totalRequests, &totalFindings)
		if err != nil {
			// Send error status to GUI
			errorMessage := fmt.Sprintf("Failed at step %d: %s", i+1, step.Description)
			sendScenarioErrorToGUI(scenario.Name, errorMessage, totalRequests, totalFindings)
			return fmt.Errorf("scenario failed at step %d (%s): %v", i+1, step.Description, err)
		}
	}

	// Send final completion to GUI with total metrics
	sendScenarioCompletionToGUI(scenario.Name, totalRequests, totalFindings)

	return nil
}

// executeAttackStep executes a net:attack step
func executeAttackStep(step ScenarioStep, attackEngine *engine.Engine, scenario *Scenario) (int, int, error) {
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

	// Prepare attack configuration
	config := &engine.AttackConfig{
		Target:      resolvedURL,
		Method:      step.Method,
		PayloadSets: step.PayloadSets,
		Headers:     make(map[string]string),
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run the attack
	result, err := attackEngine.RunAttack(ctx, config)
	if err != nil {
		return 0, 0, fmt.Errorf("attack failed: %v", err)
	}

	fmt.Printf("✅ Attack completed: %d requests, %d vulnerabilities\n", result.TotalRequests, len(result.Vulnerabilities))
	return result.TotalRequests, len(result.Vulnerabilities), nil
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

// executeCaptureStep executes a session:capture step
func executeCaptureStep(step ScenarioStep, scenario *Scenario) error {
	fmt.Printf("📸 Capturing session: %s\n", step.Description)
	// TODO: Implement session capture
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
