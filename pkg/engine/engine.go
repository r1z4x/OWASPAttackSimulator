package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/owaspattacksimulator/internal/common"
	"github.com/owaspattacksimulator/internal/mutate"
	"github.com/owaspattacksimulator/pkg/httpx"
)

// Engine represents the attack engine
type Engine struct {
	concurrency   int
	timeout       time.Duration
	mutator       *mutate.Mutator
	client        *httpx.Client
	totalRequests int
	currentAttack string // Current attack type being processed
	UI            *UI    // Enhanced UI interface
}

// AttackConfig represents attack configuration
type AttackConfig struct {
	Target      string
	Method      string
	Headers     map[string]string
	Parameters  []string
	PayloadSets []string
	Delay       int // Delay in milliseconds between requests
}

// AttackResult represents the result of an attack
type AttackResult struct {
	Target          string
	TotalRequests   int
	Vulnerabilities []Vulnerability
	Duration        time.Duration
	Findings        []common.Finding // Add findings for reporting
}

// AttackWork represents a single attack work item
type AttackWork struct {
	Parameter  string
	Payload    string
	Type       string
	AttackType string // Add attack type to work item
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	Type       string
	Parameter  string
	Payload    string
	Evidence   string
	Confidence float64
	URL        string
	StatusCode int
}

// NewEngine creates a new attack engine
func NewEngine(concurrency int, timeout time.Duration) *Engine {
	useColors := CheckTerminalSupport()
	return &Engine{
		concurrency:   concurrency,
		timeout:       timeout,
		mutator:       mutate.NewMutator(),
		client:        httpx.NewClient(timeout),
		totalRequests: 0,
		currentAttack: "",
		UI:            NewUI(useColors, true, false),
	}
}

// RunAttack performs the attack
func (e *Engine) RunAttack(config *AttackConfig) (*AttackResult, error) {
	start := time.Now()

	// Print enhanced banner and header
	e.UI.PrintBanner()
	e.UI.PrintHeader(config, e.concurrency)

	// Set default parameters if not provided
	if len(config.Parameters) == 0 {
		config.Parameters = []string{"id", "q", "search", "query", "param", "input"}
	}

	// Debug: Print parameters being used
	fmt.Printf("🔍 Using parameters: %v\n", config.Parameters)

	// Calculate total requests
	if len(config.PayloadSets) == 0 || (len(config.PayloadSets) == 1 && config.PayloadSets[0] == "all") {
		allPayloads := e.mutator.GetAllPayloads()
		totalPayloads := 0
		for _, payloads := range allPayloads {
			totalPayloads += len(payloads)
		}
		e.totalRequests = len(config.Parameters) * totalPayloads
	} else {
		e.totalRequests = len(config.Parameters) * len(config.PayloadSets) * 5
	}

	if e.totalRequests == 0 {
		e.totalRequests = 1
	}

	// Create work channel and result channel
	workChan := make(chan AttackWork, e.totalRequests)
	resultChan := make(chan *httpx.Response, e.totalRequests)

	// Start workers
	var wg sync.WaitGroup
	fmt.Printf("🔧 Starting %d worker threads\n", e.concurrency)
	for i := 0; i < e.concurrency; i++ {
		wg.Add(1)
		go e.worker(&wg, workChan, resultChan, httpx.Request{
			Method:  config.Method,
			URL:     config.Target,
			Headers: config.Headers,
		}, config.Delay)
	}

	// Collect results
	var totalRequests int
	var mu sync.Mutex
	var completedRequests int
	var rateLimited bool

	go func() {
		for resp := range resultChan {
			mu.Lock()
			totalRequests++
			completedRequests++

			// Update current attack type from response if available
			if resp != nil && resp.AttackType != "" {
				e.currentAttack = resp.AttackType
			}

			// Check for rate limiting
			if resp != nil && (isRateLimited(resp.StatusCode) || containsRateLimitMessage(string(resp.Body)) || containsRateLimitHeaders(resp.Headers)) {
				rateLimited = true
			}

			// Show progress every 5 requests or when completed
			if completedRequests%5 == 0 || completedRequests == e.totalRequests {
				e.UI.PrintProgress(completedRequests, e.totalRequests, e.currentAttack, rateLimited)

				// Add newline when completed
				if completedRequests == e.totalRequests {
					fmt.Println()
				}
			}
			mu.Unlock()
		}
	}()

	// Generate attack work
	if len(config.PayloadSets) == 0 || (len(config.PayloadSets) == 1 && config.PayloadSets[0] == "all") {
		e.generateAllPayloadWork(config.Parameters, workChan)
	} else {
		for _, payloadSet := range config.PayloadSets {
			e.generateSpecificPayloadWork(config.Parameters, payloadSet, workChan)
		}
	}

	close(workChan)
	wg.Wait()
	close(resultChan)

	duration := time.Since(start)

	result := &AttackResult{
		Target:          config.Target,
		TotalRequests:   totalRequests,
		Vulnerabilities: []Vulnerability{},
		Duration:        duration,
	}

	// Print enhanced summary
	e.UI.PrintSummary(result)

	return result, nil
}

// generateAllPayloadWork generates work for all available attack types
func (e *Engine) generateAllPayloadWork(parameters []string, workChan chan<- AttackWork) {
	// Get all available attack types from mutator
	allPayloads := e.mutator.GetAllPayloads()

	for attackType, payloads := range allPayloads {
		// Update current attack type for progress display
		e.currentAttack = attackType

		for _, parameter := range parameters {
			for _, payload := range payloads {
				work := AttackWork{
					Parameter:  parameter,
					Payload:    payload.Value,
					Type:       string(payload.Type),
					AttackType: attackType, // Add attack type to work
				}
				select {
				case workChan <- work:
					// Work sent successfully
				default:
					// Channel is full, skip this work
				}
			}
		}
	}
}

// generateSpecificPayloadWork generates work for specific payload sets
func (e *Engine) generateSpecificPayloadWork(parameters []string, payloadSet string, workChan chan<- AttackWork) {
	// Map payload set names to attack types
	attackTypeMap := map[string]string{
		"xss.reflected":            string(common.AttackXSS),
		"sqli.error":               string(common.AttackSQLi),
		"sqli.time":                string(common.AttackSQLi),
		"ssrf.basic":               string(common.AttackSSRF),
		"cmdi.shell":               string(common.AttackCommandInj),
		"ldap.injection":           string(common.AttackLDAPInjection),
		"nosql.injection":          string(common.AttackNoSQLInjection),
		"header.injection":         string(common.AttackHeaderInjection),
		"template.injection":       string(common.AttackTemplateInjection),
		"xxe.file":                 string(common.AttackXXE),
		"access.admin":             string(common.AttackBrokenAccessControl),
		"idor":                     string(common.AttackIDOR),
		"privilege.escalation":     string(common.AttackPrivilegeEscalation),
		"jwt.manipulation":         string(common.AttackJWTManipulation),
		"weak.crypto":              string(common.AttackWeakCrypto),
		"weak.hashing":             string(common.AttackWeakHashing),
		"insecure.transport":       string(common.AttackInsecureTransport),
		"business.logic":           string(common.AttackBusinessLogicFlaw),
		"race.condition":           string(common.AttackRaceCondition),
		"default.credentials":      string(common.AttackDefaultCredentials),
		"debug.mode":               string(common.AttackDebugMode),
		"verbose.errors":           string(common.AttackVerboseErrors),
		"weak.cors":                string(common.AttackWeakCORS),
		"known.vulnerability":      string(common.AttackKnownVulnerability),
		"outdated.component":       string(common.AttackOutdatedComponent),
		"version.disclosure":       string(common.AttackVersionDisclosure),
		"weak.auth":                string(common.AttackWeakAuth),
		"session.fixation":         string(common.AttackSessionFixation),
		"session.timeout":          string(common.AttackSessionTimeout),
		"weak.password":            string(common.AttackWeakPassword),
		"brute.force":              string(common.AttackBruteForce),
		"insecure.deserialization": string(common.AttackInsecureDeserialization),
		"code.injection":           string(common.AttackCodeInjection),
		"supply.chain":             string(common.AttackSupplyChainAttack),
		"log.injection":            string(common.AttackLogInjection),
		"log.bypass":               string(common.AttackLogBypass),
		"audit.tampering":          string(common.AttackAuditTrailTampering),
	}

	attackType, exists := attackTypeMap[payloadSet]
	if !exists {
		fmt.Printf("⚠️  Unknown payload set: %s\n", payloadSet)
		return
	}

	e.currentAttack = payloadSet // Set current attack type

	// Get payloads for this attack type
	payloads := e.mutator.GetPayloadsForType(common.AttackType(attackType))
	fmt.Printf("📦 Loading payload set: %s (%d payloads)\n", payloadSet, len(payloads))

	for _, parameter := range parameters {
		for _, payload := range payloads {
			work := AttackWork{
				Parameter: parameter,
				Payload:   payload.Value,
				Type:      string(payload.Type),
			}
			workChan <- work
		}
	}
}

// worker processes attack work
func (e *Engine) worker(wg *sync.WaitGroup, workChan <-chan AttackWork, resultChan chan<- *httpx.Response, baseRequest httpx.Request, delay int) {
	defer wg.Done()

	for work := range workChan {
		// Create request with payload - use a copy to avoid concurrent map access
		req := httpx.Request{
			Method:  baseRequest.Method,
			URL:     baseRequest.URL,
			Headers: make(map[string]string),
			Body:    baseRequest.Body,
			Params:  make(map[string]string),
		}

		// Copy headers safely
		for k, v := range baseRequest.Headers {
			req.Headers[k] = v
		}

		// Copy params safely
		for k, v := range baseRequest.Params {
			req.Params[k] = v
		}

		// Add the payload parameter
		req.Params[work.Parameter] = work.Payload

		// Send request
		ctx := context.Background()
		resp, err := e.client.DoRequest(ctx, &req)
		if err != nil {
			// Silent error handling
			continue
		}

		// Add attack information to response
		if resp != nil {
			resp.Parameter = work.Parameter
			resp.Payload = work.Payload
			resp.AttackType = work.AttackType // Add attack type to response
		}

		// Send result with non-blocking channel write
		select {
		case resultChan <- resp:
			// Result sent successfully
		default:
			// Channel is full, skip this result
		}

		// Apply delay between requests if specified
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

// checkVulnerabilities checks response for vulnerabilities
func (e *Engine) checkVulnerabilities(resp *httpx.Response, work AttackWork) *httpx.Response {
	// Basic vulnerability checking logic
	// This should be enhanced with proper security checks
	if work.Type == "xss" && containsXSS(string(resp.Body), work.Payload) {
		// XSS detected
		fmt.Printf("⚠️  XSS vulnerability detected in parameter %s\n", work.Parameter)
	} else if work.Type == "sqli" && containsSQLi(string(resp.Body)) {
		// SQL Injection detected
		fmt.Printf("⚠️  SQL Injection vulnerability detected in parameter %s\n", work.Parameter)
	} else if work.Type == "ssrf" && containsSSRF(string(resp.Body)) {
		// SSRF detected
		fmt.Printf("⚠️  SSRF vulnerability detected in parameter %s\n", work.Parameter)
	}

	return resp
}

// Helper functions for vulnerability detection
func containsXSS(body, payload string) bool {
	return len(body) > 0 && len(payload) > 0
}

func containsSQLi(body string) bool {
	sqlPatterns := []string{"sql syntax", "mysql error", "oracle error", "postgresql error"}
	for _, pattern := range sqlPatterns {
		if contains(body, pattern) {
			return true
		}
	}
	return false
}

func containsSSRF(body string) bool {
	ssrfPatterns := []string{"127.0.0.1", "localhost", "169.254.169.254"}
	for _, pattern := range ssrfPatterns {
		if contains(body, pattern) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr))
}

// getOWASPCategory maps attack type to OWASP category
func getOWASPCategory(attackType string) common.OWASPCategory {
	switch attackType {
	case "xss", "sqli", "ldap.injection", "nosql.injection", "command.injection":
		return common.OWASPCategoryA03Injection
	case "broken.access.control", "idor", "privilege.escalation":
		return common.OWASPCategoryA01BrokenAccessControl
	case "weak.crypto", "weak.hashing", "insecure.transport":
		return common.OWASPCategoryA02CryptographicFailures
	case "business.logic.flaw", "race.condition":
		return common.OWASPCategoryA04InsecureDesign
	case "default.credentials", "debug.mode", "verbose.errors", "missing.headers", "weak.cors":
		return common.OWASPCategoryA05SecurityMisconfiguration
	case "known.vulnerability", "outdated.component", "version.disclosure":
		return common.OWASPCategoryA03Injection // Fallback to injection
	case "weak.auth", "session.fixation", "session.timeout", "weak.password", "brute.force":
		return common.OWASPCategoryA01BrokenAccessControl // Fallback to access control
	case "insecure.deserialization", "code.injection":
		return common.OWASPCategoryA03Injection // Fallback to injection
	case "log.injection", "log.bypass", "audit.tampering":
		return common.OWASPCategoryA03Injection // Fallback to injection
	case "ssrf", "xxe":
		return common.OWASPCategoryA03Injection // Fallback to injection
	default:
		return common.OWASPCategoryA03Injection
	}
}

// determineSeverity determines severity based on status code and attack type
func determineSeverity(statusCode int, attackType string) common.Severity {
	// High severity for error responses
	if statusCode >= 500 {
		return common.SeverityHigh
	}

	// Medium severity for client errors
	if statusCode >= 400 {
		return common.SeverityMedium
	}

	// Low severity for successful responses
	return common.SeverityLow
}

// isRateLimited checks if the response indicates rate limiting
func isRateLimited(statusCode int) bool {
	// Common rate limiting status codes used by various services
	rateLimitCodes := []int{
		429, // Too Many Requests (RFC 6585)
		403, // Forbidden (often used for rate limiting)
		503, // Service Unavailable (often used for rate limiting)
		509, // Bandwidth Limit Exceeded
		420, // Enhance Your Calm (Twitter API)
		498, // Invalid Token (often used for rate limiting)
		499, // Client Closed Request (sometimes used for rate limiting)
	}

	for _, code := range rateLimitCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// containsRateLimitMessage checks if response body contains rate limiting messages
func containsRateLimitMessage(body string) bool {
	// Common rate limiting messages used by various services
	rateLimitMessages := []string{
		"rate limit",
		"rate limited",
		"too many requests",
		"quota exceeded",
		"throttled",
		"rate exceeded",
		"request limit",
		"api limit",
		"usage limit",
		"bandwidth limit",
		"rate limiting",
		"slow down",
		"enhance your calm",
		"try again later",
		"service temporarily unavailable",
		"temporarily blocked",
		"access denied",
		"forbidden",
		"blocked",
		"you are being rate limited",
	}

	bodyLower := strings.ToLower(body)
	for _, message := range rateLimitMessages {
		if strings.Contains(bodyLower, message) {
			return true
		}
	}
	return false
}

// containsRateLimitHeaders checks if response headers contain rate limiting indicators
func containsRateLimitHeaders(headers map[string]string) bool {
	// Common rate limiting header names and values
	rateLimitHeaders := map[string][]string{
		"x-ratelimit-remaining":       {"0", "false", "exceeded"},
		"x-ratelimit-limit":           {"0", "exceeded"},
		"x-ratelimit-reset":           {"0", "exceeded"},
		"retry-after":                 {"0", "exceeded"},
		"x-rate-limit-remaining":      {"0", "false", "exceeded"},
		"x-rate-limit-limit":          {"0", "exceeded"},
		"x-rate-limit-reset":          {"0", "exceeded"},
		"x-throttle-remaining":        {"0", "false", "exceeded"},
		"x-throttle-limit":            {"0", "exceeded"},
		"x-quota-remaining":           {"0", "false", "exceeded"},
		"x-quota-limit":               {"0", "exceeded"},
		"x-api-limit-remaining":       {"0", "false", "exceeded"},
		"x-api-limit-limit":           {"0", "exceeded"},
		"x-usage-limit-remaining":     {"0", "false", "exceeded"},
		"x-usage-limit-limit":         {"0", "exceeded"},
		"x-request-limit-remaining":   {"0", "false", "exceeded"},
		"x-request-limit-limit":       {"0", "exceeded"},
		"x-bandwidth-limit-remaining": {"0", "false", "exceeded"},
		"x-bandwidth-limit-limit":     {"0", "exceeded"},
	}

	// Check for rate limiting headers
	for headerName, headerValues := range rateLimitHeaders {
		if headerValue, exists := headers[headerName]; exists {
			headerValueLower := strings.ToLower(headerValue)
			for _, expectedValue := range headerValues {
				if strings.Contains(headerValueLower, expectedValue) {
					return true
				}
			}
		}
	}

	// Check for rate limiting header names (case insensitive)
	rateLimitHeaderNames := []string{
		"x-ratelimit-remaining",
		"x-ratelimit-limit",
		"x-ratelimit-reset",
		"retry-after",
		"x-rate-limit-remaining",
		"x-rate-limit-limit",
		"x-rate-limit-reset",
		"x-throttle-remaining",
		"x-throttle-limit",
		"x-quota-remaining",
		"x-quota-limit",
		"x-api-limit-remaining",
		"x-api-limit-limit",
		"x-usage-limit-remaining",
		"x-usage-limit-limit",
		"x-request-limit-remaining",
		"x-request-limit-limit",
		"x-bandwidth-limit-remaining",
		"x-bandwidth-limit-limit",
	}

	for _, headerName := range rateLimitHeaderNames {
		for actualHeaderName := range headers {
			if strings.EqualFold(actualHeaderName, headerName) {
				return true
			}
		}
	}

	return false
}
