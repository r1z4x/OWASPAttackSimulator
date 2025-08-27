package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/owaspattacksimulator/pkg/engine"
	"github.com/spf13/cobra"
)

// InteractiveCLI provides an enhanced interactive interface
type InteractiveCLI struct {
	scanner *bufio.Scanner
	engine  *engine.Engine
}

// NewInteractiveCLI creates a new interactive CLI instance
func NewInteractiveCLI() *InteractiveCLI {
	return &InteractiveCLI{
		scanner: bufio.NewScanner(os.Stdin),
		engine:  engine.NewEngine(3, 30*time.Second),
	}
}

// Run starts the interactive CLI
func (ic *InteractiveCLI) Run() {
	ic.showMainMenu()
}

// showMainMenu displays the main menu
func (ic *InteractiveCLI) showMainMenu() {
	for {
		ic.clearScreen()
		ic.printHeader()

		cyan := color.New(color.FgCyan, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		white := color.New(color.FgWhite)

		cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
		cyan.Println("║                              🎯 MAIN MENU                                   ║")
		cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

		yellow.Println("   1. 🚀 Quick Attack")
		yellow.Println("   2. 🎬 Run Scenario")
		yellow.Println("   3. ⚙️  Configuration")
		yellow.Println("   4. 📊 View Reports")
		yellow.Println("   5. 🛠️  Tools")
		yellow.Println("   6. ℹ️  Help")
		yellow.Println("   0. 🚪 Exit")

		white.Printf("\n   Enter your choice: ")

		choice := ic.getUserInput()

		switch choice {
		case "1":
			ic.quickAttack()
		case "2":
			ic.runScenario()
		case "3":
			ic.configuration()
		case "4":
			ic.viewReports()
		case "5":
			ic.tools()
		case "6":
			ic.help()
		case "0":
			ic.exit()
			return
		default:
			ic.showError("Invalid choice. Please try again.")
			ic.waitForEnter()
		}
	}
}

// quickAttack handles quick attack functionality
func (ic *InteractiveCLI) quickAttack() {
	ic.clearScreen()
	ic.printHeader()

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                              🚀 QUICK ATTACK                                ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	// Get target URL
	yellow.Printf("   🌐 Target URL: ")
	white.Printf("(e.g., https://example.com/vulnerable.php?id=1)\n   ")
	target := ic.getUserInput()
	if target == "" {
		ic.showError("Target URL is required.")
		ic.waitForEnter()
		return
	}

	// Get attack type
	yellow.Printf("   🎯 Attack Type:\n")
	yellow.Printf("      1. XSS (Cross-Site Scripting)\n")
	yellow.Printf("      2. SQL Injection\n")
	yellow.Printf("      3. SSRF (Server-Side Request Forgery)\n")
	yellow.Printf("      4. Command Injection\n")
	yellow.Printf("      5. All Attacks (Comprehensive)\n")
	white.Printf("   Enter choice (1-5): ")

	attackChoice := ic.getUserInput()
	var payloadSet string
	switch attackChoice {
	case "1":
		payloadSet = "xss.reflected"
	case "2":
		payloadSet = "sqli.error"
	case "3":
		payloadSet = "ssrf.basic"
	case "4":
		payloadSet = "cmdi.shell"
	case "5":
		payloadSet = "all"
	default:
		payloadSet = "all"
	}

	// Get concurrency
	yellow.Printf("   🚀 Concurrency (1-10): ")
	white.Printf("(default: 3)\n   ")
	concurrencyStr := ic.getUserInput()
	concurrency := 3
	if concurrencyStr != "" {
		if val, err := strconv.Atoi(concurrencyStr); err == nil && val > 0 && val <= 10 {
			concurrency = val
		}
	}

	// Confirm attack
	yellow.Printf("\n   📋 Attack Summary:\n")
	white.Printf("      Target: %s\n", target)
	white.Printf("      Attack Type: %s\n", payloadSet)
	white.Printf("      Concurrency: %d\n", concurrency)

	yellow.Printf("\n   ⚠️  Are you sure you want to proceed? (y/N): ")
	confirm := ic.getUserInput()
	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
		ic.showInfo("Attack cancelled.")
		ic.waitForEnter()
		return
	}

	// Run attack
	ic.runAttack(target, payloadSet, concurrency)
}

// runAttack executes the attack
func (ic *InteractiveCLI) runAttack(target, payloadSet string, concurrency int) {
	ic.clearScreen()

	config := &engine.AttackConfig{
		Target:      target,
		Method:      "GET",
		PayloadSets: []string{payloadSet},
		Headers:     make(map[string]string),
	}

	// Create new engine with user-specified concurrency
	attackEngine := engine.NewEngine(concurrency, 30*time.Second)

	// Run the attack
	result, err := attackEngine.RunAttack(config)
	if err != nil {
		ic.showError(fmt.Sprintf("Attack failed: %v", err))
	} else {
		ic.showSuccess("Attack completed successfully!")
		ic.showAttackResults(result)
	}

	ic.waitForEnter()
}

// runScenario handles scenario execution
func (ic *InteractiveCLI) runScenario() {
	ic.clearScreen()
	ic.printHeader()

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                              🎬 RUN SCENARIO                                ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	// List available scenarios
	yellow.Println("   📁 Available Scenarios:")
	scenarios := []string{
		"configs/scenarios/simple_attack.yaml",
		"configs/scenarios/login_and_attack.yaml",
		"configs/scenarios/browser_automation_test.yaml",
	}

	for i, scenario := range scenarios {
		white.Printf("      %d. %s\n", i+1, scenario)
	}

	white.Printf("\n   Enter scenario number or path: ")
	choice := ic.getUserInput()

	var scenarioPath string
	if num, err := strconv.Atoi(choice); err == nil && num > 0 && num <= len(scenarios) {
		scenarioPath = scenarios[num-1]
	} else {
		scenarioPath = choice
	}

	if scenarioPath == "" {
		ic.showError("Invalid scenario selection.")
		ic.waitForEnter()
		return
	}

	// Run scenario using existing command
	ic.runScenarioCommand(scenarioPath)
}

// runScenarioCommand executes scenario using the existing command structure
func (ic *InteractiveCLI) runScenarioCommand(scenarioPath string) {
	ic.clearScreen()
	ic.showInfo(fmt.Sprintf("Running scenario: %s", scenarioPath))

	// Create a temporary command to use existing scenario logic
	cmd := &cobra.Command{}
	cmd.Flags().String("file", scenarioPath, "")
	cmd.Flags().Int("concurrency", 5, "")
	cmd.Flags().String("timeout", "60s", "")

	// This would need to be integrated with the existing scenario command logic
	ic.showInfo("Scenario execution would be implemented here.")
	ic.waitForEnter()
}

// configuration handles configuration options
func (ic *InteractiveCLI) configuration() {
	ic.clearScreen()
	ic.printHeader()

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                              ⚙️  CONFIGURATION                               ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	yellow.Println("   1. 🎨 Toggle Colors")
	yellow.Println("   2. 📊 Set Default Concurrency")
	yellow.Println("   3. ⏱️  Set Default Timeout")
	yellow.Println("   4. 🔧 Advanced Settings")
	yellow.Println("   0. ↩️  Back to Main Menu")

	white.Printf("\n   Enter your choice: ")
	choice := ic.getUserInput()

	switch choice {
	case "1":
		ic.toggleColors()
	case "2":
		ic.setDefaultConcurrency()
	case "3":
		ic.setDefaultTimeout()
	case "4":
		ic.advancedSettings()
	case "0":
		return
	default:
		ic.showError("Invalid choice.")
		ic.waitForEnter()
	}
}

// viewReports handles report viewing
func (ic *InteractiveCLI) viewReports() {
	ic.clearScreen()
	ic.printHeader()

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                              📊 VIEW REPORTS                                 ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	yellow.Println("   1. 📈 Recent Attacks")
	yellow.Println("   2. 🎯 Vulnerability Summary")
	yellow.Println("   3. 📋 Export Reports")
	yellow.Println("   4. 🗑️  Clear Reports")
	yellow.Println("   0. ↩️  Back to Main Menu")

	white.Printf("\n   Enter your choice: ")
	choice := ic.getUserInput()

	switch choice {
	case "1":
		ic.showRecentAttacks()
	case "2":
		ic.showVulnerabilitySummary()
	case "3":
		ic.exportReports()
	case "4":
		ic.clearReports()
	case "0":
		return
	default:
		ic.showError("Invalid choice.")
		ic.waitForEnter()
	}
}

// tools handles additional tools
func (ic *InteractiveCLI) tools() {
	ic.clearScreen()
	ic.printHeader()

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                              🛠️  TOOLS                                      ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	yellow.Println("   1. 🔍 URL Crawler")
	yellow.Println("   2. 📝 HAR Analyzer")
	yellow.Println("   3. 🔐 Payload Generator")
	yellow.Println("   4. 🌐 Network Scanner")
	yellow.Println("   0. ↩️  Back to Main Menu")

	white.Printf("\n   Enter your choice: ")
	choice := ic.getUserInput()

	switch choice {
	case "1":
		ic.urlCrawler()
	case "2":
		ic.harAnalyzer()
	case "3":
		ic.payloadGenerator()
	case "4":
		ic.networkScanner()
	case "0":
		return
	default:
		ic.showError("Invalid choice.")
		ic.waitForEnter()
	}
}

// help shows help information
func (ic *InteractiveCLI) help() {
	ic.clearScreen()
	ic.printHeader()

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                              ℹ️  HELP                                        ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	yellow.Println("   🚀 Quick Attack:")
	white.Println("      Perform a single attack against a target URL")

	yellow.Println("   🎬 Run Scenario:")
	white.Println("      Execute a predefined attack scenario")

	yellow.Println("   ⚙️  Configuration:")
	white.Println("      Customize tool settings and preferences")

	yellow.Println("   📊 View Reports:")
	white.Println("      View and export attack results")

	yellow.Println("   🛠️  Tools:")
	white.Println("      Additional security testing tools")

	yellow.Println("\n   📞 Support:")
	white.Println("      For more help, visit: https://github.com/owaspattacksimulator")

	ic.waitForEnter()
}

// exit handles application exit
func (ic *InteractiveCLI) exit() {
	ic.clearScreen()
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	cyan.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	cyan.Println("║                              👋 GOODBYE!                                    ║")
	cyan.Println("╚══════════════════════════════════════════════════════════════════════════════╝")

	green.Println("   Thank you for using OWASP Attack Simulator!")
	green.Println("   Stay secure! 🔒")

	fmt.Println("")
}

// Helper methods
func (ic *InteractiveCLI) clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func (ic *InteractiveCLI) printHeader() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("   OWASP Attack Simulator v1.0 - Interactive Mode")
	cyan.Println("   ═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("")
}

func (ic *InteractiveCLI) getUserInput() string {
	ic.scanner.Scan()
	return strings.TrimSpace(ic.scanner.Text())
}

func (ic *InteractiveCLI) waitForEnter() {
	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Printf("\n   Press Enter to continue...")
	ic.getUserInput()
}

func (ic *InteractiveCLI) showError(message string) {
	red := color.New(color.FgRed, color.Bold)
	red.Printf("   ❌ %s\n", message)
}

func (ic *InteractiveCLI) showSuccess(message string) {
	green := color.New(color.FgGreen, color.Bold)
	green.Printf("   ✅ %s\n", message)
}

func (ic *InteractiveCLI) showInfo(message string) {
	blue := color.New(color.FgBlue, color.Bold)
	blue.Printf("   ℹ️  %s\n", message)
}

func (ic *InteractiveCLI) showWarning(message string) {
	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Printf("   ⚠️  %s\n", message)
}

// Placeholder methods for additional functionality
func (ic *InteractiveCLI) toggleColors() {
	ic.showInfo("Color toggle functionality would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) setDefaultConcurrency() {
	ic.showInfo("Default concurrency setting would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) setDefaultTimeout() {
	ic.showInfo("Default timeout setting would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) advancedSettings() {
	ic.showInfo("Advanced settings would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) showRecentAttacks() {
	ic.showInfo("Recent attacks view would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) showVulnerabilitySummary() {
	ic.showInfo("Vulnerability summary would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) exportReports() {
	ic.showInfo("Report export functionality would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) clearReports() {
	ic.showInfo("Report clearing functionality would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) urlCrawler() {
	ic.showInfo("URL crawler tool would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) harAnalyzer() {
	ic.showInfo("HAR analyzer tool would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) payloadGenerator() {
	ic.showInfo("Payload generator tool would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) networkScanner() {
	ic.showInfo("Network scanner tool would be implemented here.")
	ic.waitForEnter()
}

func (ic *InteractiveCLI) showAttackResults(result *engine.AttackResult) {
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Println("\n   📊 Attack Results:")
	yellow.Printf("      Target: ")
	white.Printf("%s\n", result.Target)
	yellow.Printf("      Total Requests: ")
	green.Printf("%d\n", result.TotalRequests)
	yellow.Printf("      Duration: ")
	white.Printf("%s\n", result.Duration)
	yellow.Printf("      Vulnerabilities Found: ")
	if len(result.Vulnerabilities) > 0 {
		red.Printf("%d\n", len(result.Vulnerabilities))
	} else {
		green.Printf("0\n")
	}
}
