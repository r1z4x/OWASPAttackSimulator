package engine

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

// UI represents the enhanced CLI interface
type UI struct {
	useColors   bool
	useProgress bool
	interactive bool
	bar         *progressbar.ProgressBar
	startTime   time.Time
	lastUpdate  time.Time
}

// NewUI creates a new enhanced UI instance
func NewUI(useColors, useProgress, interactive bool) *UI {
	return &UI{
		useColors:   useColors,
		useProgress: useProgress,
		interactive: interactive,
		startTime:   time.Now(),
	}
}

// PrintBanner prints a reverse engineering themed banner
func (ui *UI) PrintBanner() {
	if !ui.useColors {
		fmt.Println()
		fmt.Println()
		fmt.Println("__________       _______________________       ___       ________________________")
		fmt.Println("__  __ \\_ |     / /__    |_  ___/__  __ \\      __ |     / /_  ___/__  __/_  ____/")
		fmt.Println("_  / / /_ | /| / /__  /| |____ \\__  /_/ /________ | /| / /_____ \\__  /  _  / __  ")
		fmt.Println("/ /_/ /__ |/ |/ / _  ___ |___/ /_  ____/_/_____/_ |/ |/ / ____/ /_  /   / /_/ /  ")
		fmt.Println("\\____/ ____/|__/  /_/  |_/____/ /_/            ____/|__/  /____/ /_/    \\____/ ")
		fmt.Println()
		fmt.Println()
		fmt.Printf("OWASP-WSGT Attack Simulator %s\n", "v0.1.0")
		fmt.Println("Comprehensive Security Testing Framework")
		fmt.Println("Infinite-Step Attack Infrastructure")
		fmt.Println()
		fmt.Println()
		return
	}

	// Color definitions
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	magenta := color.New(color.FgMagenta, color.Bold)

	fmt.Println()
	fmt.Println()
	red.Println("	__________       _______________________       ___       ________________________")
	green.Println("	__  __ \\_ |     / /__    |_  ___/__  __ \\      __ |     / /_  ___/__  __/_  ____/")
	blue.Println("	_  / / /_ | /| / /__  /| |____ \\__  /_/ /________ | /| / /_____ \\__  /  _  / __  ")
	yellow.Println("	/ /_/ /__ |/ |/ / _  ___ |___/ /_  ____/_/_____/_ |/ |/ / ____/ /_  /   / /_/ /  ")
	cyan.Println("	\\____/ ____/|__/  /_/  |_/____/ /_/            ____/|__/  /____/ /_/    \\____/ ")
	fmt.Println()
	fmt.Println()
	magenta.Printf("OWASP-WSGT Attack Simulator %s\n", "v0.1.0")
	green.Printf("Comprehensive Security Testing Framework\n")
	blue.Printf("Infinite-Step Attack Infrastructure\n")
	fmt.Println()
	fmt.Println()
}

// PrintHeader prints a clean header inspired by mpvc design
func (ui *UI) PrintHeader(config *AttackConfig, concurrency int) {
	if !ui.useColors {
		fmt.Println()
		fmt.Println("----------------------------------------[ + Target Information ]----------------------------------------")
		fmt.Println()
		fmt.Printf("Target: %s\n", config.Target)

		fmt.Println()
		fmt.Println("----------------------------------------[ + Configuration Details ]----------------------------------------")
		fmt.Println()

		fmt.Printf("Method: %s | Threads: %d | Timeout: %s\n", config.Method, concurrency, "30s")
		if len(config.PayloadSets) > 0 {
			fmt.Printf("Payload Sets: %s\n", strings.Join(config.PayloadSets, ", "))
		}
		if len(config.Parameters) > 0 {
			fmt.Printf("Parameters: %s\n", strings.Join(config.Parameters, ", "))
		}
		fmt.Println("")
		return
	}

	// Clean header inspired by mpvc
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	white := color.New(color.FgWhite, color.Bold)

	fmt.Println()
	cyan.Println("----------------------------------------[ + Target Information ]----------------------------------------")
	fmt.Println()
	yellow.Printf("Target: ")
	white.Printf("%s\n", config.Target)

	if len(config.Headers) > 0 {
		yellow.Printf("Headers: ")
		white.Printf("%d custom headers\n", len(config.Headers))
	}

	fmt.Println()
	cyan.Println("----------------------------------------[ + Configuration Details ]----------------------------------------")
	fmt.Println()
	yellow.Printf("Method: ")
	green.Printf("%s", config.Method)
	yellow.Printf(" | Threads: ")
	green.Printf("%d", concurrency)
	yellow.Printf(" | Timeout: ")
	green.Printf("%s\n", "30s")

	if len(config.PayloadSets) > 0 {
		yellow.Printf("Payload Sets: ")
		green.Printf("%s\n", strings.Join(config.PayloadSets, ", "))
	}

	if len(config.Parameters) > 0 {
		yellow.Printf("Parameters: ")
		green.Printf("%s\n", strings.Join(config.Parameters, ", "))
	}

	fmt.Println("")
}

// PrintProgress prints a clean progress display inspired by mpvc
func (ui *UI) PrintProgress(completed, total int, currentAttack string, rateLimited bool) {
	percentage := float64(completed) / float64(total) * 100
	elapsed := time.Since(ui.startTime)
	eta := time.Duration(0)
	if completed > 0 {
		eta = time.Duration(float64(elapsed) * float64(total-completed) / float64(completed))
	}

	// Get attack info - no truncation for better readability
	attackInfo := ui.getShortAttackName(currentAttack)
	if attackInfo == "" {
		attackInfo = "Initializing..."
	}

	if !ui.useColors {
		// Simple progress without colors
		barWidth := 20
		filled := int(float64(barWidth) * percentage / 100)
		bar := strings.Repeat("=", filled) + strings.Repeat("_", barWidth-filled)

		fmt.Printf("\r[ %s ] %d/%d (%.1f%%) | %s | %s | %-20s",
			bar, completed, total, percentage, elapsed.Round(time.Second), eta.Round(time.Second), attackInfo)

		// Add newline when completed to separate from summary
		if completed == total {
			fmt.Println()
		}
		return
	}

	// Clean progress with colors
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	white := color.New(color.FgWhite)

	// Create progress bar with colors
	barWidth := 20
	filled := int(float64(barWidth) * percentage / 100)

	var bar string
	if percentage < 30 {
		bar = red.Sprint(strings.Repeat("=", filled)) + white.Sprint(strings.Repeat("_", barWidth-filled))
	} else if percentage < 70 {
		bar = yellow.Sprint(strings.Repeat("=", filled)) + white.Sprint(strings.Repeat("_", barWidth-filled))
	} else {
		bar = green.Sprint(strings.Repeat("=", filled)) + white.Sprint(strings.Repeat("_", barWidth-filled))
	}

	// Print progress with proper line clearing and padding
	cyan.Printf("\r[ ")
	fmt.Print(bar)
	cyan.Printf(" ] ")
	white.Printf("%d/%d (%.1f%%) | ", completed, total, percentage)
	yellow.Printf("%s", elapsed.Round(time.Second))
	white.Printf(" | ")
	green.Printf("%s", eta.Round(time.Second))
	white.Printf(" | ")
	cyan.Printf("%-20s", attackInfo) // Fixed width to prevent overlap
	
	// Show rate limiting status if applicable
	if rateLimited {
		red := color.New(color.FgRed, color.Bold)
		red.Printf(" | RATE LIMITED")
	}

	// Add newline when completed to separate from summary
	if completed == total {
		fmt.Println()
	}

}

// PrintVulnerability prints vulnerability findings with enhanced formatting
func (ui *UI) PrintVulnerability(vuln *Vulnerability) {
	if !ui.useColors {
		fmt.Printf("⚠️  %s vulnerability detected in parameter %s\n", vuln.Type, vuln.Parameter)
		return
	}

	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	white := color.New(color.FgWhite)

	red.Printf("⚠️  VULNERABILITY DETECTED!\n")
	yellow.Printf("Type: ")
	white.Printf("%s\n", vuln.Type)
	yellow.Printf("Parameter: ")
	white.Printf("%s\n", vuln.Parameter)
	yellow.Printf("Payload: ")
	cyan.Printf("%s\n", vuln.Payload)
	yellow.Printf("URL: ")
	white.Printf("%s\n", vuln.URL)
	yellow.Printf("Status Code: ")
	white.Printf("%d\n", vuln.StatusCode)
	yellow.Printf("Confidence: ")
	white.Printf("%.1f%%\n", vuln.Confidence*100)
	if vuln.Evidence != "" {
		yellow.Printf("Evidence: ")
		white.Printf("%s\n", vuln.Evidence)
	}
	fmt.Println("")
}

// PrintSummary prints a clean summary inspired by mpvc design
func (ui *UI) PrintSummary(result *AttackResult) {
	if !ui.useColors {
		fmt.Println()
		fmt.Println("----------------------------------------[ + Attack Summary ]----------------------------------------")
		fmt.Println()
		fmt.Printf("[-] Target: %s\n", ui.truncateString(result.Target, 70))
		fmt.Printf("[-] Requests: %d | Duration: %s | Speed: %.1f req/s\n",
			result.TotalRequests, result.Duration.Round(time.Millisecond),
			float64(result.TotalRequests)/result.Duration.Seconds())
		if len(result.Vulnerabilities) > 0 {
			fmt.Printf("[-] Vulnerabilities Found: %d\n", len(result.Vulnerabilities))
		} else {
			fmt.Printf("[-] No vulnerabilities detected\n")
		}
		fmt.Println()
		return
	}

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	white := color.New(color.FgWhite, color.Bold)

	fmt.Println()
	fmt.Println()
	fmt.Println()
	cyan.Println("----------------------------------------[ + Attack Summary ]----------------------------------------")
	fmt.Println()

	yellow.Printf("[i] Target: ")
	white.Printf("%s\n", ui.truncateString(result.Target, 70))

	yellow.Printf("[i] Requests: ")
	green.Printf("%d", result.TotalRequests)
	yellow.Printf(" | Duration: ")
	green.Printf("%s", result.Duration.Round(time.Millisecond))
	yellow.Printf(" | Speed: ")
	green.Printf("%.1f req/s\n", float64(result.TotalRequests)/result.Duration.Seconds())

	yellow.Printf("[i] Vulnerabilities: ")
	if len(result.Vulnerabilities) > 0 {
		red.Printf("%d found\n", len(result.Vulnerabilities))

		// Print vulnerability breakdown
		vulnTypes := make(map[string]int)
		for _, vuln := range result.Vulnerabilities {
			vulnTypes[vuln.Type]++
		}

		yellow.Printf("[i] Breakdown:\n")
		for vulnType, count := range vulnTypes {
			white.Printf("  %s: %d\n", vulnType, count)
		}
	} else {
		green.Printf("None detected\n")
	}

	// Print security score
	securityScore := ui.calculateSecurityScore(result)
	yellow.Printf("[i] Security Score: ")
	ui.printSecurityScore(securityScore)

	fmt.Println()
}

// PrintStepInfo prints step information with enhanced formatting
func (ui *UI) PrintStepInfo(stepIndex, totalSteps int, stepDescription, stepType string) {
	if !ui.useColors {
		fmt.Printf("📋 Step %d/%d: %s (%s)\n", stepIndex+1, totalSteps, stepDescription, stepType)
		return
	}

	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgBlue, color.Bold)
	white := color.New(color.FgWhite)

	cyan.Printf("📋 Step ")
	yellow.Printf("%d/%d", stepIndex+1, totalSteps)
	cyan.Printf(": ")
	white.Printf("%s", stepDescription)
	cyan.Printf(" (")
	blue.Printf("%s", stepType)
	cyan.Printf(")\n")
}

// PrintSuccess prints success messages with enhanced formatting
func (ui *UI) PrintSuccess(message string) {
	if !ui.useColors {
		fmt.Printf("[+] %s\n", message)
		return
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("[+] %s\n", message)
}

// PrintError prints error messages with enhanced formatting
func (ui *UI) PrintError(message string) {
	if !ui.useColors {
		fmt.Printf("[!] %s\n", message)
		return
	}

	red := color.New(color.FgRed, color.Bold)
	red.Printf("[!] %s\n", message)
}

// PrintWarning prints warning messages with enhanced formatting
func (ui *UI) PrintWarning(message string) {
	if !ui.useColors {
		fmt.Printf("[!] %s\n", message)
		return
	}

	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Printf("[!] %s\n", message)
}

// PrintInfo prints info messages with enhanced formatting
func (ui *UI) PrintInfo(message string) {
	if !ui.useColors {
		fmt.Printf("[i] %s\n", message)
		return
	}

	blue := color.New(color.FgBlue, color.Bold)
	blue.Printf("[i] %s\n", message)
}

// Helper methods
func (ui *UI) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func (ui *UI) getShortAttackName(attackType string) string {
	shortNames := map[string]string{
		"xss":                      "XSS",
		"sqli":                     "SQLi",
		"ssrf":                     "SSRF",
		"cmdi":                     "CMDi",
		"ldap":                     "LDAP",
		"xxe":                      "XXE",
		"idor":                     "IDOR",
		"jwt":                      "JWT",
		"weak_crypto":              "WeakCrypto",
		"weak_auth":                "WeakAuth",
		"default_credentials":      "DefCreds",
		"weak_password":            "WeakPass",
		"cors":                     "CORS",
		"audit":                    "Audit",
		"nosql_injection":          "NoSQL",
		"header_injection":         "Header",
		"template_injection":       "Template",
		"access_admin":             "Admin",
		"privilege_escalation":     "PrivEsc",
		"jwt_manipulation":         "JWTManip",
		"insecure_transport":       "Insecure",
		"business_logic":           "BizLogic",
		"race_condition":           "Race",
		"debug_mode":               "Debug",
		"verbose_errors":           "Verbose",
		"weak_cors":                "WeakCORS",
		"known_vulnerability":      "KnownVuln",
		"outdated_component":       "Outdated",
		"version_disclosure":       "Version",
		"session_fixation":         "SessFix",
		"session_timeout":          "SessTimeout",
		"brute_force":              "Brute",
		"insecure_deserialization": "Deserial",
		"code_injection":           "CodeInj",
		"supply_chain":             "SupplyChain",
		"log_injection":            "LogInj",
		"log_bypass":               "LogBypass",
		"audit_tampering":          "AuditTamper",
		"weak_hashing":             "WeakHash",
		"command_injection":        "CmdInj",
		"missing":                  "Missing",
		"unknown":                  "Unknown",
	}

	if shortName, exists := shortNames[attackType]; exists {
		return shortName
	}

	attackTypeLower := strings.ToLower(attackType)
	for key, shortName := range shortNames {
		if strings.Contains(attackTypeLower, strings.ToLower(key)) {
			return shortName
		}
	}

	if len(attackType) > 8 {
		return attackType[:8]
	}
	return attackType
}

func (ui *UI) calculateSecurityScore(result *AttackResult) float64 {
	if result.TotalRequests == 0 {
		return 100.0
	}

	vulnRatio := float64(len(result.Vulnerabilities)) / float64(result.TotalRequests)
	score := 100.0 - (vulnRatio * 100.0)

	if score < 0 {
		score = 0
	}

	return score
}

func (ui *UI) printSecurityScore(score float64) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	switch {
	case score >= 90:
		green.Printf("%.1f%% (Excellent)\n", score)
	case score >= 70:
		yellow.Printf("%.1f%% (Good)\n", score)
	case score >= 50:
		yellow.Printf("%.1f%% (Fair)\n", score)
	default:
		red.Printf("%.1f%% (Poor)\n", score)
	}
}

// CheckTerminalSupport checks if the terminal supports colors
func CheckTerminalSupport() bool {
	// Check if NO_COLOR environment variable is set
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check if FORCE_COLOR environment variable is set
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}

	// Check if we're in a terminal
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}

	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
