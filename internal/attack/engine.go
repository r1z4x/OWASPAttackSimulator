package attack

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/owaspattacksimulator/internal/common"
	"github.com/owaspattacksimulator/internal/httpx"
	"github.com/owaspattacksimulator/internal/mutate"
)

// Engine represents the attack engine
type Engine struct {
	workers       int
	timeout       time.Duration
	mutator       *mutate.Mutator
	client        *httpx.Client
	totalRequests int
	currentAttack string // Current attack type being processed
	UI            *UI    // Enhanced UI interface
	debug         bool   // Debug mode flag
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
func NewEngine(workers int, timeout time.Duration) *Engine {
	useColors := CheckTerminalSupport()
	return &Engine{
		workers:       workers,
		timeout:       timeout,
		mutator:       mutate.NewMutator(),
		client:        httpx.NewClient(timeout),
		totalRequests: 0,
		currentAttack: "",
		UI:            NewUI(useColors, true, false),
		debug:         false,
	}
}

// SetDebugMode enables or disables debug mode
func (e *Engine) SetDebugMode(debug bool) {
	e.debug = debug
}

// RunAttack performs the attack
func (e *Engine) RunAttack(config *AttackConfig) (*AttackResult, error) {
	start := time.Now()

	// Print enhanced banner and header
	e.UI.PrintBanner()
	e.UI.PrintHeader(config, e.workers)

	// Set default parameters if not provided
	if len(config.Parameters) == 0 {
		config.Parameters = []string{"id", "q", "search", "query", "param", "input"}
	}

	// Debug: Print parameters being used
	fmt.Printf("🔍 Using parameters: %v\n", config.Parameters)

	// Calculate total requests - we'll calculate this properly after generating work
	e.totalRequests = 0

	// Create work channel and result channel
	workChan := make(chan AttackWork, e.totalRequests)
	resultChan := make(chan *httpx.Response, e.totalRequests)

	// Start workers
	var wg sync.WaitGroup
	fmt.Printf("🔧 Starting %d worker threads\n", e.workers)

	// If workers is 1, use sequential processing for better delay control
	if e.workers == 1 {
		wg.Add(1)
		go e.sequentialWorker(&wg, workChan, resultChan, httpx.Request{
			Method:  config.Method,
			URL:     config.Target,
			Headers: config.Headers,
		}, config.Delay)
	} else {
		for i := 0; i < e.workers; i++ {
			wg.Add(1)
			go e.worker(&wg, workChan, resultChan, httpx.Request{
				Method:  config.Method,
				URL:     config.Target,
				Headers: config.Headers,
			}, config.Delay)
		}
	}

	// Collect results and findings
	var mu sync.Mutex
	var completedRequests int
	var rateLimited bool
	var allFindings []common.Finding

	go func() {
		for resp := range resultChan {
			mu.Lock()
			completedRequests++

			// Update current attack type from response if available
			if resp != nil && resp.AttackType != "" {
				e.currentAttack = resp.AttackType
			}

			// Collect findings from response
			if resp != nil {
				findings := e.analyzeResponseForFindings(resp)
				if len(findings) > 0 {
					allFindings = append(allFindings, findings...)
				}
			}

			// Check for rate limiting
			//if resp != nil && (isRateLimited(resp.StatusCode) || containsRateLimitMessage(string(resp.Body)) || containsRateLimitHeaders(resp.Headers)) {
			//	rateLimited = true
			//}

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

	// Generate attack work and calculate total requests
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
		TotalRequests:   completedRequests,
		Vulnerabilities: []Vulnerability{},
		Duration:        duration,
		Findings:        allFindings, // Add collected findings
	}

	// Print enhanced summary
	e.UI.PrintSummary(result)

	return result, nil
}

// generateAllPayloadWork generates work for all available attack types
func (e *Engine) generateAllPayloadWork(parameters []string, workChan chan<- AttackWork) {
	// Get all available attack types from mutator
	allPayloads := e.mutator.GetAllPayloads()

	// Calculate total requests
	totalRequests := 0
	for _, payloads := range allPayloads {
		totalRequests += len(parameters) * len(payloads)
	}
	e.totalRequests = totalRequests

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

	// Calculate total requests for this payload set
	e.totalRequests = len(parameters) * len(payloads)

	for _, parameter := range parameters {
		for _, payload := range payloads {
			work := AttackWork{
				Parameter:  parameter,
				Payload:    payload.Value,
				Type:       string(payload.Type),
				AttackType: attackType, // Add attack type to work
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

		// Show debug information if enabled
		if e.debug {
			fmt.Printf("\n🔍 [DEBUG] Testing: %s %s\n", req.Method, req.URL)
			fmt.Printf("   Parameter: %s\n", work.Parameter)
			fmt.Printf("   Payload: %s\n", work.Payload)
			fmt.Printf("   Attack Type: %s\n", work.AttackType)
			if len(req.Headers) > 0 {
				fmt.Printf("   Headers: %v\n", req.Headers)
			}
			if len(req.Params) > 0 {
				fmt.Printf("   Params: %v\n", req.Params)
			}
		}

		// Send request
		ctx := context.Background()
		resp, err := e.client.DoRequest(ctx, &req)
		if err != nil {
			if e.debug {
				fmt.Printf("   ❌ [DEBUG] Request failed: %v\n", err)
			}
			// Silent error handling
			continue
		}

		// Add attack information to response
		if resp != nil {
			resp.Parameter = work.Parameter
			resp.Payload = work.Payload
			resp.AttackType = work.AttackType // Add attack type to response
			resp.Method = req.Method          // Add method to response

			// Show response debug information if enabled
			if e.debug {
				fmt.Printf("   📡 [DEBUG] Response: %d (Size: %d bytes)\n", resp.StatusCode, len(resp.Body))
				if len(resp.Headers) > 0 {
					fmt.Printf("   Response Headers: %v\n", resp.Headers)
				}
				if len(resp.Body) > 0 {
					bodyStr := string(resp.Body)
					if len(bodyStr) > 200 {
						bodyStr = bodyStr[:200] + "..."
					}
					fmt.Printf("   Response Body: %s\n", bodyStr)
				}
			}
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
			if e.debug {
				fmt.Printf("   ⏳ [DEBUG] Applying delay of %dms between requests\n", delay)
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

// sequentialWorker processes attack work sequentially (for single thread mode)
func (e *Engine) sequentialWorker(wg *sync.WaitGroup, workChan <-chan AttackWork, resultChan chan<- *httpx.Response, baseRequest httpx.Request, delay int) {
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

		// Show debug information if enabled
		if e.debug {
			fmt.Printf("\n🔍 [DEBUG] Testing: %s %s\n", req.Method, req.URL)
			fmt.Printf("   Parameter: %s\n", work.Parameter)
			fmt.Printf("   Payload: %s\n", work.Payload)
			fmt.Printf("   Attack Type: %s\n", work.AttackType)
			if len(req.Headers) > 0 {
				fmt.Printf("   Headers: %v\n", req.Headers)
			}
			if len(req.Params) > 0 {
				fmt.Printf("   Params: %v\n", req.Params)
			}
		}

		// Send request
		ctx := context.Background()
		resp, err := e.client.DoRequest(ctx, &req)
		if err != nil {
			if e.debug {
				fmt.Printf("   ❌ [DEBUG] Request failed: %v\n", err)
			}
			// Silent error handling
			continue
		}

		// Add attack information to response
		if resp != nil {
			resp.Parameter = work.Parameter
			resp.Payload = work.Payload
			resp.AttackType = work.AttackType // Add attack type to response
			resp.Method = req.Method          // Add method to response

			// Show response debug information if enabled
			if e.debug {
				fmt.Printf("   📡 [DEBUG] Response: %d (Size: %d bytes)\n", resp.StatusCode, len(resp.Body))
				if len(resp.Headers) > 0 {
					fmt.Printf("   Response Headers: %v\n", resp.Headers)
				}
				if len(resp.Body) > 0 {
					bodyStr := string(resp.Body)
					if len(bodyStr) > 200 {
						bodyStr = bodyStr[:200] + "..."
					}
					fmt.Printf("   Response Body: %s\n", bodyStr)
				}
			}
		}

		// Send result with non-blocking channel write
		select {
		case resultChan <- resp:
			// Result sent successfully
		default:
			// Channel is full, skip this result
		}

		// Apply delay between requests if specified (always applied in sequential mode)
		if delay > 0 {
			if e.debug {
				fmt.Printf("   ⏳ [DEBUG] Applying delay of %dms between requests (sequential mode)\n", delay)
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
}

// getOWASPCategoryForAttackType returns the appropriate OWASP category for an attack type
func (e *Engine) getOWASPCategoryForAttackType(attackType string) common.OWASPCategory {
	switch attackType {
	// A01:2021 - Broken Access Control
	case string(common.AttackBrokenAccessControl), string(common.AttackIDOR),
		string(common.AttackPrivilegeEscalation), string(common.AttackJWTManipulation):
		return common.OWASPCategoryA01BrokenAccessControl

	// A02:2021 - Cryptographic Failures
	case string(common.AttackWeakCrypto), string(common.AttackWeakHashing),
		string(common.AttackInsecureTransport), string(common.AttackWeakRandomness):
		return common.OWASPCategoryA02CryptographicFailures

	// A03:2021 - Injection
	case string(common.AttackXSS), string(common.AttackSQLi), string(common.AttackCommandInj),
		string(common.AttackLDAPInjection), string(common.AttackNoSQLInjection),
		string(common.AttackHeaderInjection), string(common.AttackTemplateInjection):
		return common.OWASPCategoryA03Injection

	// A04:2021 - Insecure Design
	case string(common.AttackBusinessLogicFlaw), string(common.AttackRaceCondition),
		string(common.AttackInsecureWorkflow):
		return common.OWASPCategoryA04InsecureDesign

	// A05:2021 - Security Misconfiguration
	case string(common.AttackDefaultCredentials), string(common.AttackDebugMode),
		string(common.AttackVerboseErrors), string(common.AttackMissingHeaders),
		string(common.AttackWeakCORS):
		return common.OWASPCategoryA05SecurityMisconfiguration

	// A06:2021 - Vulnerable and Outdated Components
	case string(common.AttackKnownVulnerability), string(common.AttackOutdatedComponent),
		string(common.AttackVersionDisclosure):
		return common.OWASPCategoryA06VulnerableComponents

	// A07:2021 - Identification and Authentication Failures
	case string(common.AttackWeakAuth), string(common.AttackSessionFixation),
		string(common.AttackSessionTimeout), string(common.AttackWeakPassword),
		string(common.AttackBruteForce):
		return common.OWASPCategoryA07AuthFailures

	// A08:2021 - Software and Data Integrity Failures
	case string(common.AttackInsecureDeserialization), string(common.AttackCodeInjection),
		string(common.AttackSupplyChainAttack):
		return common.OWASPCategoryA08SoftwareDataIntegrity

	// A09:2021 - Security Logging and Monitoring Failures
	case string(common.AttackLogInjection), string(common.AttackLogBypass),
		string(common.AttackAuditTrailTampering):
		return common.OWASPCategoryA09LoggingFailures

	// A10:2021 - Server-Side Request Forgery
	case string(common.AttackSSRF), string(common.AttackXXE), string(common.AttackOpenRedirect):
		return common.OWASPCategoryA10SSRF

	default:
		return common.OWASPCategoryA05SecurityMisconfiguration
	}
}

// getVariantForPayload returns the variant name for a given payload
func (e *Engine) getVariantForPayload(attackType string, payload string) string {
	if e.debug {
		fmt.Printf("🔍 [DEBUG] getVariantForPayload: attackType=%s, payload=%s\n", attackType, payload)
	}

	// Get all payloads for this attack type
	payloads := e.mutator.GetPayloadsForType(common.AttackType(attackType))

	if e.debug {
		fmt.Printf("🔍 [DEBUG] Found %d payloads for attack type %s\n", len(payloads), attackType)
	}

	// Find the payload and return its variant
	for _, p := range payloads {
		if p.Value == payload {
			if e.debug {
				fmt.Printf("🔍 [DEBUG] Found variant: %s\n", p.Variant)
			}
			return p.Variant
		}
	}

	// If not found, return a default variant name
	if e.debug {
		fmt.Printf("🔍 [DEBUG] Variant not found, returning unknown_variant\n")
	}
	return "unknown_variant"
}

// analyzeResponseForFindings analyzes a response and returns findings
func (e *Engine) analyzeResponseForFindings(resp *httpx.Response) []common.Finding {
	var findings []common.Finding

	if resp == nil {
		return findings
	}

	// Get the correct OWASP category for this attack type
	category := e.getOWASPCategoryForAttackType(resp.AttackType)

	// Get the variant name for this payload
	variant := e.getVariantForPayload(resp.AttackType, resp.Payload)

	// Analyze response for security indicators
	blocked := e.isBlocked(resp)
	rateLimited := e.isRateLimited(resp)
	forbidden := e.isForbidden(resp)
	serverError := e.isServerError(resp)

	// Create raw request and response data
	requestRaw := e.createRawRequest(resp)
	responseRaw := e.createRawResponse(resp)

	// Create a basic finding for each response
	finding := common.Finding{
		ID:             fmt.Sprintf("response_%d_%s", resp.StatusCode, resp.AttackType),
		Type:           variant,  // Use variant name instead of generic type
		Category:       category, // Use correct OWASP category
		Title:          fmt.Sprintf("%s - %s", variant, resp.AttackType),
		Description:    fmt.Sprintf("Tested %s variant for %s attack type", variant, resp.AttackType),
		Evidence:       e.generateEvidence(resp, blocked, rateLimited, forbidden, serverError),
		Payload:        resp.Payload,
		URL:            resp.URL,
		Method:         resp.Method,
		ResponseStatus: resp.StatusCode,
		ResponseSize:   int64(len(resp.Body)),
		ResponseTime:   resp.Duration,
		Blocked:        blocked,
		RateLimited:    rateLimited,
		Forbidden:      forbidden,
		ServerError:    serverError,
		Timestamp:      time.Now(),
		RequestRaw:     requestRaw,
		ResponseRaw:    responseRaw,
	}
	findings = append(findings, finding)

	return findings
}

// isBlocked checks if the response indicates WAF/IPS blocking
func (e *Engine) isBlocked(resp *httpx.Response) bool {
	// Check for common WAF/IPS blocking indicators
	blockedStatusCodes := []int{403, 406, 429, 444, 499, 502, 503, 504}
	for _, code := range blockedStatusCodes {
		if resp.StatusCode == code {
			return true
		}
	}

	// Check response body for blocking indicators
	bodyStr := strings.ToLower(string(resp.Body))
	blockingKeywords := []string{
		"blocked", "forbidden", "access denied", "security violation",
		"waf", "firewall", "ips", "intrusion", "malicious", "suspicious",
		"request blocked", "security policy", "threat detected",
		"cloudflare", "akamai", "imperva", "f5", "barracuda",
	}
	for _, keyword := range blockingKeywords {
		if strings.Contains(bodyStr, keyword) {
			return true
		}
	}

	// Check headers for blocking indicators
	for headerName, headerValue := range resp.Headers {
		headerStr := strings.ToLower(headerName + ": " + headerValue)
		for _, keyword := range blockingKeywords {
			if strings.Contains(headerStr, keyword) {
				return true
			}
		}
	}

	return false
}

// createRawRequest creates a raw HTTP request string from response data
func (e *Engine) createRawRequest(resp *httpx.Response) string {
	var requestData strings.Builder

	// Parse URL to get path and query
	parsedURL, err := url.Parse(resp.URL)
	if err != nil {
		return "Invalid URL"
	}

	// Build request line
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	requestData.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", resp.Method, path))

	// Add headers
	if host := parsedURL.Host; host != "" {
		requestData.WriteString(fmt.Sprintf("Host: %s\n", host))
	}
	requestData.WriteString("User-Agent: OWASPAttackSimulator/1.0\n")
	requestData.WriteString("Accept: */*\n")
	requestData.WriteString("Accept-Language: en-US,en;q=0.9\n")
	requestData.WriteString("Accept-Encoding: gzip, deflate\n")
	requestData.WriteString("Connection: keep-alive\n")

	// Add content type and length if there's a payload
	if resp.Payload != "" {
		requestData.WriteString("Content-Type: application/x-www-form-urlencoded\n")
		requestData.WriteString(fmt.Sprintf("Content-Length: %d\n", len(resp.Payload)))
		requestData.WriteString("\n")
		requestData.WriteString(resp.Payload)
	} else {
		requestData.WriteString("\n")
	}

	return requestData.String()
}

// createRawResponse creates a raw HTTP response string from response data
func (e *Engine) createRawResponse(resp *httpx.Response) string {
	var responseData strings.Builder

	// Build status line
	statusText := e.getStatusText(resp.StatusCode)
	responseData.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", resp.StatusCode, statusText))

	// Add headers
	for key, value := range resp.Headers {
		responseData.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	// Add default headers if not present
	if _, exists := resp.Headers["Server"]; !exists {
		responseData.WriteString("Server: nginx/1.20.1\n")
	}
	if _, exists := resp.Headers["Date"]; !exists {
		responseData.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\n")
	}
	if _, exists := resp.Headers["Content-Type"]; !exists {
		responseData.WriteString("Content-Type: text/html; charset=utf-8\n")
	}
	if _, exists := resp.Headers["Content-Length"]; !exists {
		responseData.WriteString(fmt.Sprintf("Content-Length: %d\n", len(resp.Body)))
	}
	if _, exists := resp.Headers["Connection"]; !exists {
		responseData.WriteString("Connection: keep-alive\n")
	}

	// Add security headers if detected
	if e.isBlocked(resp) {
		responseData.WriteString("X-WAF-Status: blocked\n")
		responseData.WriteString("X-Security: WAF detected\n")
	}
	if e.isRateLimited(resp) {
		responseData.WriteString("X-RateLimit-Status: limited\n")
		responseData.WriteString("Retry-After: 60\n")
	}

	responseData.WriteString("\n")

	// Add response body
	if len(resp.Body) > 0 {
		responseData.WriteString(string(resp.Body))
	} else {
		// Simulate response body based on status code
		switch resp.StatusCode {
		case 200:
			responseData.WriteString("<html><body><h1>OK</h1><p>Request processed successfully</p></body></html>")
		case 403:
			responseData.WriteString("<html><body><h1>Forbidden</h1><p>Access denied by security policy</p></body></html>")
		case 429:
			responseData.WriteString("<html><body><h1>Too Many Requests</h1><p>Rate limit exceeded</p></body></html>")
		case 500:
			responseData.WriteString("<html><body><h1>Internal Server Error</h1><p>Server encountered an error</p></body></html>")
		default:
			responseData.WriteString("<html><body><h1>Response</h1><p>Security scan response</p></body></html>")
		}
	}

	return responseData.String()
}

// getStatusText returns HTTP status text for status code
func (e *Engine) getStatusText(statusCode int) string {
	switch statusCode {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Unknown"
	}
}

// isRateLimited checks if the response indicates rate limiting
func (e *Engine) isRateLimited(resp *httpx.Response) bool {
	// Check for rate limiting status codes
	if resp.StatusCode == 429 {
		return true
	}

	// Check response body for rate limiting indicators
	bodyStr := strings.ToLower(string(resp.Body))
	rateLimitKeywords := []string{
		"rate limit", "rate limiting", "too many requests", "throttled",
		"quota exceeded", "request limit", "try again later", "slow down",
		"rate exceeded", "limit exceeded", "too frequent",
	}
	for _, keyword := range rateLimitKeywords {
		if strings.Contains(bodyStr, keyword) {
			return true
		}
	}

	// Check headers for rate limiting indicators
	for headerName, headerValue := range resp.Headers {
		headerStr := strings.ToLower(headerName + ": " + headerValue)
		for _, keyword := range rateLimitKeywords {
			if strings.Contains(headerStr, keyword) {
				return true
			}
		}
	}

	return false
}

// isForbidden checks if the response indicates forbidden access
func (e *Engine) isForbidden(resp *httpx.Response) bool {
	// Check status codes
	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return true
	}

	// Check response body for forbidden indicators
	bodyStr := strings.ToLower(string(resp.Body))
	forbiddenPatterns := []string{
		"forbidden", "access denied", "unauthorized", "permission denied",
		"insufficient privileges", "access restricted", "not authorized",
		"authentication required", "login required", "credentials required",
		"access control", "authorization failed", "permission error",
	}

	for _, pattern := range forbiddenPatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}

	// Check headers for authentication requirements
	for headerName := range resp.Headers {
		headerLower := strings.ToLower(headerName)
		if headerLower == "www-authenticate" || headerLower == "proxy-authenticate" {
			return true
		}
		if headerLower == "x-auth-required" || headerLower == "x-access-denied" {
			return true
		}
	}

	return false
}

// isServerError checks if the response indicates server error
func (e *Engine) isServerError(resp *httpx.Response) bool {
	// Check status codes
	if resp.StatusCode >= 500 && resp.StatusCode < 600 {
		return true
	}

	// Check response body for server error indicators
	bodyStr := strings.ToLower(string(resp.Body))
	serverErrorPatterns := []string{
		"internal server error", "server error", "application error",
		"runtime error", "fatal error", "critical error", "system error",
		"database error", "connection error", "timeout error",
		"service unavailable", "bad gateway", "gateway timeout",
		"http 500", "http 502", "http 503", "http 504", "http 505",
		"error occurred", "an error occurred", "something went wrong",
		"technical difficulties", "maintenance mode", "under maintenance",
	}

	for _, pattern := range serverErrorPatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}

	// Check for specific error patterns in different frameworks
	frameworkErrorPatterns := []string{
		"asp.net", "php fatal", "java exception", "python traceback",
		"ruby error", "node.js error", "express error", "django error",
		"flask error", "spring error", "hibernate error", "jdbc error",
		"mysql error", "postgresql error", "oracle error", "sql server error",
	}

	for _, pattern := range frameworkErrorPatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}

	return false
}

// hasUnusualResponsePattern checks for unusual response patterns
func (e *Engine) hasUnusualResponsePattern(resp *httpx.Response) bool {
	// Check for very large responses (potential data dump)
	if len(resp.Body) > 100000 {
		return true
	}

	// Check for very small responses (potential error)
	if len(resp.Body) < 100 && resp.StatusCode != 204 {
		return true
	}

	// Check for unusual content types
	contentType := resp.Headers["content-type"]
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "text/html") {
		return true
	}

	return false
}

// generateEvidence generates evidence based on response analysis
func (e *Engine) generateEvidence(resp *httpx.Response, blocked, rateLimited, forbidden, serverError bool) string {
	var evidence []string

	if blocked {
		evidence = append(evidence, "WAF/IPS blocking detected")
	}
	if rateLimited {
		evidence = append(evidence, "Rate limiting detected")
	}
	if forbidden {
		evidence = append(evidence, "Access forbidden")
	}
	if serverError {
		evidence = append(evidence, "Server error response")
	}

	if len(evidence) == 0 {
		return fmt.Sprintf("HTTP %d response received", resp.StatusCode)
	}

	return strings.Join(evidence, "; ")
}
