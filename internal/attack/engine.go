package attack

import (
	"context"
	"encoding/json"
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
	Target       string
	Method       string
	Headers      map[string]string
	Parameters   []string
	PayloadSets  []string
	VariationSet []string             // New field for specifying which variations to use
	Delay        int                  // Delay in milliseconds between requests
	BodyConfig   *BodyVariationConfig // Body variation configuration
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
	workChan := make(chan AttackWork, 10000)        // Large buffer
	resultChan := make(chan *httpx.Response, 10000) // Large buffer

	// Generate attack work first to calculate total requests
	if len(config.PayloadSets) == 0 || (len(config.PayloadSets) == 1 && config.PayloadSets[0] == "all") {
		e.generateComprehensiveAttackWork(config.Parameters, nil, config.VariationSet) // Pass nil to just calculate
	} else {
		e.generateSpecificPayloadWork(config.Parameters, config.PayloadSets[0], nil, config.VariationSet) // Pass nil to just calculate
	}

	// Debug: Print calculated total requests
	if e.debug {
		fmt.Printf("🔍 [DEBUG] Calculated total requests: %d\n", e.totalRequests)
	}

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
		}, config.Delay, config.BodyConfig)
	} else {
		for i := 0; i < e.workers; i++ {
			wg.Add(1)
			go e.worker(&wg, workChan, resultChan, httpx.Request{
				Method:  config.Method,
				URL:     config.Target,
				Headers: config.Headers,
			}, config.Delay, config.BodyConfig)
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

	// Generate and send work to channel
	actualWorkCount := 0
	if len(config.PayloadSets) == 0 || (len(config.PayloadSets) == 1 && config.PayloadSets[0] == "all") {
		actualWorkCount = e.generateComprehensiveAttackWork(config.Parameters, workChan, config.VariationSet)
	} else {
		actualWorkCount = e.generateSpecificPayloadWork(config.Parameters, config.PayloadSets[0], workChan, config.VariationSet)
	}

	// Update total requests with actual work count if different
	if actualWorkCount > 0 && actualWorkCount != e.totalRequests {
		if e.debug {
			fmt.Printf("🔍 [DEBUG] Adjusting total requests from %d to %d (actual work count)\n", e.totalRequests, actualWorkCount)
		}
		e.totalRequests = actualWorkCount
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

// generateComprehensiveAttackWork generates work including all mutator variations
func (e *Engine) generateComprehensiveAttackWork(parameters []string, workChan chan<- AttackWork, variationSet []string) int {
	// If workChan is nil, just calculate total requests
	calculateOnly := workChan == nil
	// Get all available attack types from mutator
	allPayloads := e.mutator.GetAllPayloads()

	// Debug: Print payload information
	if !calculateOnly {
		totalPayloads := 0
		for _, payloads := range allPayloads {
			totalPayloads += len(payloads)
		}
	}

	// Calculate total requests including selected variations
	totalRequests := 0
	for _, payloads := range allPayloads {
		// Basic payloads
		totalRequests += len(parameters) * len(payloads)

		// Method variations (7 methods per payload, limited to first 3)
		if e.shouldIncludeVariation("method", variationSet) {
			methodCount := 0
			for i := range payloads {
				if i >= 3 { // Limit to first 3 payloads
					break
				}
				methodCount += 7 // 7 methods per payload
			}
			totalRequests += methodCount
		}

		// Header variations (14 common headers per payload, limited to first 3)
		if e.shouldIncludeVariation("header", variationSet) {
			headerCount := 0
			for i := range payloads {
				if i >= 3 { // Limit to first 3 payloads
					break
				}
				headerCount += 14 // 14 headers per payload
			}
			totalRequests += headerCount
		}

		// Body variations (4 body types per payload, limited to first 3)
		if e.shouldIncludeVariation("body", variationSet) {
			bodyCount := 0
			contentTypeCount := 0
			for i := range payloads {
				if i >= 3 { // Limit to first 3 payloads
					break
				}
				bodyCount += 4            // 4 body types per payload
				contentTypeCount += 4 * 2 // 2 content type variants per body type
			}
			totalRequests += bodyCount + contentTypeCount
		}

		// Combination variations (2 combinations per payload, limited to first 2)
		if e.shouldIncludeVariation("combination", variationSet) {
			combinationCount := 0
			for i := range payloads {
				if i >= 2 { // Limit to first 2 payloads
					break
				}
				combinationCount += 2 // 2 combinations per payload
			}
			totalRequests += combinationCount
		}
	}
	e.totalRequests = totalRequests

	if !calculateOnly {
		fmt.Printf("🔍 [DEBUG] Calculated total requests: %d\n", totalRequests)
	}

	// Generate comprehensive work including all variations
	for attackType, payloads := range allPayloads {
		e.currentAttack = attackType

		// Skip work generation if only calculating
		if calculateOnly {
			continue
		}

		// 1. Basic payload work
		for _, parameter := range parameters {
			for _, payload := range payloads {
				work := AttackWork{
					Parameter:  parameter,
					Payload:    payload.Value,
					Type:       string(payload.Type),
					AttackType: attackType,
				}
				select {
				case workChan <- work:
					// Work sent successfully
				default:
					// Channel is full, skip this work
				}
			}
		}

		// 2. Method variations for each payload (only for first few payloads to avoid too many requests)
		if e.shouldIncludeVariation("method", variationSet) {
			methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
			for i, payload := range payloads {
				// Limit method variations to first 3 payloads per attack type
				if i >= 3 {
					break
				}
				for _, method := range methods {
					work := AttackWork{
						Parameter:  "method_variation",
						Payload:    payload.Value,
						Type:       string(payload.Type),
						AttackType: attackType + "_method_" + strings.ToLower(method),
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

		// 3. Header variations for each payload (only for first few payloads)
		if e.shouldIncludeVariation("header", variationSet) {
			commonHeaders := []string{"User-Agent", "Referer", "Cookie", "Accept", "Accept-Language", "Accept-Encoding", "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization", "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded"}
			for i, payload := range payloads {
				// Limit header variations to first 3 payloads per attack type
				if i >= 3 {
					break
				}
				for _, header := range commonHeaders {
					work := AttackWork{
						Parameter:  "header_variation",
						Payload:    payload.Value,
						Type:       string(payload.Type),
						AttackType: attackType + "_header_" + strings.ToLower(header),
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

		// 4. Body variations for each payload (only for first few payloads)
		if e.shouldIncludeVariation("body", variationSet) {
			bodyTypes := []string{"json", "form", "xml", "multipart"}
			for i, payload := range payloads {
				// Limit body variations to first 3 payloads per attack type
				if i >= 3 {
					break
				}
				for _, bodyType := range bodyTypes {
					// Basic body variation
					work := AttackWork{
						Parameter:  "body_variation",
						Payload:    payload.Value,
						Type:       string(payload.Type),
						AttackType: attackType + "_body_" + bodyType,
					}
					select {
					case workChan <- work:
						// Work sent successfully
					default:
						// Channel is full, skip this work
					}

					// Content type variants (limited to first 2 variants per body type)
					contentTypeVariants := e.getContentTypeVariants(bodyType)
					for j, variant := range contentTypeVariants {
						if j >= 2 { // Limit to first 2 variants
							break
						}
						work := AttackWork{
							Parameter:  "body_variation_with_content_type",
							Payload:    payload.Value,
							Type:       string(payload.Type),
							AttackType: attackType + "_body_" + bodyType + "_content_type_" + strings.ReplaceAll(variant, "/", "_"),
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

		// 5. Combination variations (header + URL, URL + body) - only for first few payloads
		if e.shouldIncludeVariation("combination", variationSet) {
			for i, payload := range payloads {
				// Limit combination variations to first 2 payloads per attack type
				if i >= 2 {
					break
				}
				// Header + URL combination
				work := AttackWork{
					Parameter:  "combination_header_url",
					Payload:    payload.Value,
					Type:       string(payload.Type),
					AttackType: attackType + "_combination_header_url",
				}
				select {
				case workChan <- work:
					// Work sent successfully
				default:
					// Channel is full, skip this work
				}

				// URL + Body combination
				work2 := AttackWork{
					Parameter:  "combination_url_body",
					Payload:    payload.Value,
					Type:       string(payload.Type),
					AttackType: attackType + "_combination_url_body",
				}
				select {
				case workChan <- work2:
					// Work sent successfully
				default:
					// Channel is full, skip this work
				}
			}
		}
	}

	if !calculateOnly {
		fmt.Printf("🔍 [DEBUG] Finished generating work\n")
	}

	// Return actual work count
	if calculateOnly {
		return e.totalRequests
	}

	// Count actual work items sent to channel
	actualWorkCount := 0
	for _, payloads := range allPayloads {
		// Basic payloads
		actualWorkCount += len(parameters) * len(payloads)

		// Method variations
		if e.shouldIncludeVariation("method", variationSet) {
			for i := range payloads {
				if i >= 3 {
					break
				}
				actualWorkCount += 7
			}
		}

		// Header variations
		if e.shouldIncludeVariation("header", variationSet) {
			for i := range payloads {
				if i >= 3 {
					break
				}
				actualWorkCount += 14
			}
		}

		// Body variations
		if e.shouldIncludeVariation("body", variationSet) {
			for i := range payloads {
				if i >= 3 {
					break
				}
				actualWorkCount += 4 + 8 // 4 body types + 8 content type variants
			}
		}

		// Combination variations
		if e.shouldIncludeVariation("combination", variationSet) {
			for i := range payloads {
				if i >= 2 {
					break
				}
				actualWorkCount += 2
			}
		}
	}

	return actualWorkCount
}

// generateSpecificPayloadWork generates work for specific payload sets
func (e *Engine) generateSpecificPayloadWork(parameters []string, payloadSet string, workChan chan<- AttackWork, variationSet []string) int {
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
		return 0
	}

	e.currentAttack = payloadSet // Set current attack type

	// Get payloads for this attack type
	payloads := e.mutator.GetPayloadsForType(common.AttackType(attackType))

	// Calculate total requests for this payload set - include selected variations
	e.totalRequests = len(parameters) * len(payloads)

	// Add method variations (limited to first 3 payloads)
	if e.shouldIncludeVariation("method", variationSet) {
		methodCount := 0
		for i := range payloads {
			if i >= 3 { // Limit to first 3 payloads
				break
			}
			methodCount += 7 // 7 methods per payload
		}
		e.totalRequests += methodCount
	}

	// Add header variations (limited to first 3 payloads)
	if e.shouldIncludeVariation("header", variationSet) {
		headerCount := 0
		for i := range payloads {
			if i >= 3 { // Limit to first 3 payloads
				break
			}
			headerCount += 14 // 14 headers per payload
		}
		e.totalRequests += headerCount
	}

	// Add body variations (limited to first 3 payloads)
	if e.shouldIncludeVariation("body", variationSet) {
		bodyCount := 0
		for i := range payloads {
			if i >= 3 { // Limit to first 3 payloads
				break
			}
			bodyCount += 4 // 4 body types per payload
		}
		e.totalRequests += bodyCount
	}

	// Add combination variations (limited to first 2 payloads)
	if e.shouldIncludeVariation("combination", variationSet) {
		combinationCount := 0
		for i := range payloads {
			if i >= 2 { // Limit to first 2 payloads
				break
			}
			combinationCount += 2 // 2 combinations per payload
		}
		e.totalRequests += combinationCount
	}

	// Add encoded variations (limited to first 2 payloads, up to 4 encodings each)
	if e.shouldIncludeVariation("encoded", variationSet) {
		encodedCount := 0
		for i := range payloads {
			if i >= 2 { // Limit to first 2 payloads
				break
			}
			encodedCount += 4 // 4 encodings per payload
		}
		e.totalRequests += encodedCount
	}

	// If workChan is nil, just calculate
	if workChan == nil {
		return e.totalRequests
	}

	// 1. Basic payload work
	for _, parameter := range parameters {
		for _, payload := range payloads {
			work := AttackWork{
				Parameter:  parameter,
				Payload:    payload.Value,
				Type:       string(payload.Type),
				AttackType: attackType,
			}
			workChan <- work
		}
	}

	// 2. Method variations for each payload (only for first few payloads)
	if e.shouldIncludeVariation("method", variationSet) {
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
		for i, payload := range payloads {
			// Limit method variations to first 3 payloads per attack type
			if i >= 3 {
				break
			}
			for _, method := range methods {
				work := AttackWork{
					Parameter:  "method_variation",
					Payload:    payload.Value,
					Type:       string(payload.Type),
					AttackType: attackType + "_method_" + strings.ToLower(method),
				}
				workChan <- work
			}
		}
	}

	// 3. Header variations for each payload (only for first few payloads)
	if e.shouldIncludeVariation("header", variationSet) {
		commonHeaders := []string{"User-Agent", "Referer", "Cookie", "Accept", "Accept-Language", "Accept-Encoding", "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization", "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded"}
		for i, payload := range payloads {
			// Limit header variations to first 3 payloads per attack type
			if i >= 3 {
				break
			}
			for _, header := range commonHeaders {
				work := AttackWork{
					Parameter:  "header_variation",
					Payload:    payload.Value,
					Type:       string(payload.Type),
					AttackType: attackType + "_header_" + strings.ToLower(header),
				}
				workChan <- work
			}
		}
	}

	// 4. Body variations for each payload (only for first few payloads)
	if e.shouldIncludeVariation("body", variationSet) {
		bodyTypes := []string{"json", "form", "xml", "multipart"}
		for i, payload := range payloads {
			// Limit body variations to first 3 payloads per attack type
			if i >= 3 {
				break
			}
			for _, bodyType := range bodyTypes {
				work := AttackWork{
					Parameter:  "body_variation",
					Payload:    payload.Value,
					Type:       string(payload.Type),
					AttackType: attackType + "_body_" + bodyType,
				}
				workChan <- work
			}
		}
	}

	// 5. Encoded variations (URL, Double URL, Hex, Unicode) - only for first few payloads
	if e.shouldIncludeVariation("encoded", variationSet) {
		for i, payload := range payloads {
			// Limit encoded variations to first 2 payloads per attack type
			if i >= 2 {
				break
			}

			// URL encoded variation
			urlEncoded := url.QueryEscape(payload.Value)
			if urlEncoded != payload.Value {
				work := AttackWork{
					Parameter:  "encoded_url",
					Payload:    urlEncoded,
					Type:       string(payload.Type),
					AttackType: attackType + "_encoded_url",
				}
				workChan <- work
			}

			// Double URL encoded variation
			doubleEncoded := url.QueryEscape(url.QueryEscape(payload.Value))
			if doubleEncoded != payload.Value && doubleEncoded != urlEncoded {
				work := AttackWork{
					Parameter:  "encoded_double_url",
					Payload:    doubleEncoded,
					Type:       string(payload.Type),
					AttackType: attackType + "_encoded_double_url",
				}
				workChan <- work
			}

			// Hex encoded variation
			hexEncoded := e.hexEncode(payload.Value)
			if hexEncoded != payload.Value {
				work := AttackWork{
					Parameter:  "encoded_hex",
					Payload:    hexEncoded,
					Type:       string(payload.Type),
					AttackType: attackType + "_encoded_hex",
				}
				workChan <- work
			}

			// Unicode encoded variation
			unicodeEncoded := e.unicodeEncode(payload.Value)
			if unicodeEncoded != payload.Value {
				work := AttackWork{
					Parameter:  "encoded_unicode",
					Payload:    unicodeEncoded,
					Type:       string(payload.Type),
					AttackType: attackType + "_encoded_unicode",
				}
				workChan <- work
			}
		}
	}

	// 6. Combination variations (header + URL, URL + body) - only for first few payloads
	if e.shouldIncludeVariation("combination", variationSet) {
		for i, payload := range payloads {
			// Limit combination variations to first 2 payloads per attack type
			if i >= 2 {
				break
			}
			// Header + URL combination
			work := AttackWork{
				Parameter:  "combination_header_url",
				Payload:    payload.Value,
				Type:       string(payload.Type),
				AttackType: attackType + "_combination_header_url",
			}
			workChan <- work

			// URL + Body combination
			work2 := AttackWork{
				Parameter:  "combination_url_body",
				Payload:    payload.Value,
				Type:       string(payload.Type),
				AttackType: attackType + "_combination_url_body",
			}
			workChan <- work2
		}
	}

	// Return actual work count
	actualWorkCount := len(parameters) * len(payloads)

	// Method variations
	if e.shouldIncludeVariation("method", variationSet) {
		for i := range payloads {
			if i >= 3 {
				break
			}
			actualWorkCount += 7
		}
	}

	// Header variations
	if e.shouldIncludeVariation("header", variationSet) {
		for i := range payloads {
			if i >= 3 {
				break
			}
			actualWorkCount += 14
		}
	}

	// Body variations
	if e.shouldIncludeVariation("body", variationSet) {
		for i := range payloads {
			if i >= 3 {
				break
			}
			actualWorkCount += 4
		}
	}

	// Encoded variations
	if e.shouldIncludeVariation("encoded", variationSet) {
		for i := range payloads {
			if i >= 2 {
				break
			}
			actualWorkCount += 4
		}
	}

	// Combination variations
	if e.shouldIncludeVariation("combination", variationSet) {
		for i := range payloads {
			if i >= 2 {
				break
			}
			actualWorkCount += 2
		}
	}

	return actualWorkCount
}

// generateAllPayloadWork generates work for all available attack types
func (e *Engine) generateAllPayloadWork(parameters []string, workChan chan<- AttackWork, variationSet []string) int {
	// Use comprehensive attack work generation
	return e.generateComprehensiveAttackWork(parameters, workChan, variationSet)
}

// worker processes attack work
func (e *Engine) worker(wg *sync.WaitGroup, workChan <-chan AttackWork, resultChan chan<- *httpx.Response, baseRequest httpx.Request, delay int, bodyConfig *BodyVariationConfig) {
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

		// Handle different variation types
		switch work.Parameter {
		case "method_variation":
			// Extract method from attack type
			if strings.Contains(work.AttackType, "_method_") {
				parts := strings.Split(work.AttackType, "_method_")
				if len(parts) > 1 {
					req.Method = strings.ToUpper(parts[1])
				}
			}
			// Add payload to URL parameters
			req.Params["id"] = work.Payload

		case "header_variation":
			// Extract header name from attack type
			if strings.Contains(work.AttackType, "_header_") {
				parts := strings.Split(work.AttackType, "_header_")
				if len(parts) > 1 {
					req.Headers[parts[1]] = work.Payload
				}
			}
			// Add payload to URL parameters
			req.Params["id"] = work.Payload

		case "body_variation":
			// Extract body type from attack type
			if strings.Contains(work.AttackType, "_body_") {
				parts := strings.Split(work.AttackType, "_body_")
				if len(parts) > 1 {
					req.Body = []byte(fmt.Sprintf(`{"data": "%s"}`, work.Payload))
					req.Headers["Content-Type"] = "application/json"
					req.Headers["Content-Length"] = fmt.Sprintf("%d", len(req.Body))
				}
			}
			// Add payload to URL parameters
			req.Params["id"] = work.Payload

		case "combination_header_url":
			// Add payload to headers
			req.Headers["User-Agent"] = work.Payload
			req.Headers["Referer"] = work.Payload
			// Add payload to URL parameters
			req.Params["id"] = work.Payload

		case "combination_url_body":
			// Add payload to URL parameters
			req.Params["id"] = work.Payload
			// Add payload to body
			if strings.Contains(req.Headers["Content-Type"], "application/json") {
				req.Body = []byte(fmt.Sprintf(`{"data": "%s"}`, work.Payload))
			} else {
				req.Body = []byte(fmt.Sprintf("data=%s", work.Payload))
			}

		default:
			// Standard parameter injection
			req.Params[work.Parameter] = work.Payload
		}

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
			if len(req.Body) > 0 {
				fmt.Printf("   Body: %s\n", string(req.Body))
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
func (e *Engine) sequentialWorker(wg *sync.WaitGroup, workChan <-chan AttackWork, resultChan chan<- *httpx.Response, baseRequest httpx.Request, delay int, bodyConfig *BodyVariationConfig) {
	defer wg.Done()

	for work := range workChan {
		// Create request with payload - use a copy to avoid concurrent map access
		req := httpx.Request{
			Method:  baseRequest.Method,
			URL:     baseRequest.URL,
			Headers: make(map[string]string),
			Body:    make([]byte, len(baseRequest.Body)),
			Params:  make(map[string]string),
		}

		// Copy body safely
		copy(req.Body, baseRequest.Body)

		// Copy headers safely
		for k, v := range baseRequest.Headers {
			req.Headers[k] = v
		}

		// Copy params safely
		for k, v := range baseRequest.Params {
			req.Params[k] = v
		}

		// Handle different variation types
		switch work.Parameter {
		case "method_variation":
			// Extract method from attack type
			if strings.Contains(work.AttackType, "_method_") {
				parts := strings.Split(work.AttackType, "_method_")
				if len(parts) > 1 {
					req.Method = strings.ToUpper(parts[1])
				}
			}
			// Add payload to URL parameters
			req.Params["id"] = work.Payload

		case "header_variation":
			// Extract header name from attack type
			if strings.Contains(work.AttackType, "_header_") {
				parts := strings.Split(work.AttackType, "_header_")
				if len(parts) > 1 {
					req.Headers[parts[1]] = work.Payload
				}
			}
			// Add payload to URL parameters
			req.Params["id"] = work.Payload

		case "body_variation":
			// Extract body type from attack type
			if strings.Contains(work.AttackType, "_body_") {
				parts := strings.Split(work.AttackType, "_body_")
				if len(parts) > 1 {
					bodyType := parts[1]
					body, contentType := e.createBodyVariation(bodyType, work.Payload, bodyConfig)
					req.Body = body
					req.Headers["Content-Type"] = contentType
					req.Headers["Content-Length"] = fmt.Sprintf("%d", len(req.Body))
				}
			}
			// Add payload to URL parameters as well
			req.Params["id"] = work.Payload

		case "body_variation_with_content_type":
			// Extract body type and content type from attack type
			if strings.Contains(work.AttackType, "_body_") && strings.Contains(work.AttackType, "_content_type_") {
				// Parse: attackType_body_bodyType_content_type_contentType
				parts := strings.Split(work.AttackType, "_body_")
				if len(parts) > 1 {
					bodyAndContentType := parts[1]
					contentTypeParts := strings.Split(bodyAndContentType, "_content_type_")
					if len(contentTypeParts) > 1 {
						bodyType := contentTypeParts[0]
						contentType := strings.ReplaceAll(contentTypeParts[1], "_", "/")

						body, _ := e.createBodyVariation(bodyType, work.Payload, bodyConfig)
						req.Body = body
						req.Headers["Content-Type"] = contentType
						req.Headers["Content-Length"] = fmt.Sprintf("%d", len(req.Body))
					}
				}
			}
			// Add payload to URL parameters as well
			req.Params["id"] = work.Payload

		case "combination_header_url":
			// Add payload to headers
			req.Headers["User-Agent"] = work.Payload
			req.Headers["Referer"] = work.Payload
			// Add payload to URL parameters
			req.Params["id"] = work.Payload

		case "combination_url_body":
			// Add payload to URL parameters
			req.Params["id"] = work.Payload
			// Add payload to body
			if strings.Contains(req.Headers["Content-Type"], "application/json") {
				req.Body = []byte(fmt.Sprintf(`{"data": "%s"}`, work.Payload))
			} else {
				req.Body = []byte(fmt.Sprintf("data=%s", work.Payload))
			}

		default:
			// Standard parameter injection
			req.Params[work.Parameter] = work.Payload
		}

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
			if len(req.Body) > 0 {
				fmt.Printf("   Body: %s\n", string(req.Body))
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
		// For unknown attack types, try to determine category from attack type name
		attackTypeLower := strings.ToLower(attackType)

		// Handle body variation attack types by extracting base attack type
		if strings.Contains(attackTypeLower, "_body_") {
			parts := strings.Split(attackTypeLower, "_body_")
			if len(parts) > 0 {
				baseAttackType := parts[0]
				// Recursively call with base attack type
				return e.getOWASPCategoryForAttackType(baseAttackType)
			}
		}

		// Handle method variation attack types
		if strings.Contains(attackTypeLower, "_method_") {
			parts := strings.Split(attackTypeLower, "_method_")
			if len(parts) > 0 {
				baseAttackType := parts[0]
				return e.getOWASPCategoryForAttackType(baseAttackType)
			}
		}

		// Handle header variation attack types
		if strings.Contains(attackTypeLower, "_header_") {
			parts := strings.Split(attackTypeLower, "_header_")
			if len(parts) > 0 {
				baseAttackType := parts[0]
				return e.getOWASPCategoryForAttackType(baseAttackType)
			}
		}

		// Check for specific patterns in attack type
		if strings.Contains(attackTypeLower, "xss") || strings.Contains(attackTypeLower, "injection") {
			return common.OWASPCategoryA03Injection
		}
		if strings.Contains(attackTypeLower, "auth") || strings.Contains(attackTypeLower, "login") {
			return common.OWASPCategoryA07AuthFailures
		}
		if strings.Contains(attackTypeLower, "crypto") || strings.Contains(attackTypeLower, "hash") {
			return common.OWASPCategoryA02CryptographicFailures
		}
		if strings.Contains(attackTypeLower, "access") || strings.Contains(attackTypeLower, "idor") {
			return common.OWASPCategoryA01BrokenAccessControl
		}
		if strings.Contains(attackTypeLower, "ssrf") || strings.Contains(attackTypeLower, "xxe") {
			return common.OWASPCategoryA10SSRF
		}

		// If still unknown, return a generic category instead of A05
		return common.OWASPCategoryA03Injection // Most common for unknown attack types
	}
}

// getVariantForPayload returns the variant name for a given payload
func (e *Engine) getVariantForPayload(attackType string, payload string) string {
	if e.debug {
		fmt.Printf("🔍 [DEBUG] getVariantForPayload: attackType=%s, payload=%s\n", attackType, payload)
	}

	// Handle method variations and combination variations
	if strings.Contains(attackType, "_method_") {
		// Extract base attack type from method variation
		parts := strings.Split(attackType, "_method_")
		if len(parts) > 0 {
			baseAttackType := parts[0]
			payloads := e.mutator.GetPayloadsForType(common.AttackType(baseAttackType))

			// Find the payload and return its variant with method suffix
			for _, p := range payloads {
				if p.Value == payload {
					method := strings.ToUpper(parts[1])
					return p.Variant + "_method_" + method
				}
			}

			// If payload not found in base attack type, return a meaningful variant
			method := strings.ToUpper(parts[1])
			return baseAttackType + "_method_" + method
		}
		return "method_variation"
	}

	if strings.Contains(attackType, "_header_") {
		// Extract base attack type from header variation
		parts := strings.Split(attackType, "_header_")
		if len(parts) > 0 {
			baseAttackType := parts[0]
			payloads := e.mutator.GetPayloadsForType(common.AttackType(baseAttackType))

			// Find the payload and return its variant with header suffix
			for _, p := range payloads {
				if p.Value == payload {
					header := parts[1]
					return p.Variant + "_header_" + header
				}
			}

			// If payload not found in base attack type, return a meaningful variant
			header := parts[1]
			return baseAttackType + "_header_" + header
		}
		return "header_variation"
	}

	if strings.Contains(attackType, "_body_") {
		// Handle body_variation_with_content_type specially
		if strings.Contains(attackType, "_content_type_") {
			// Parse: attackType_body_bodyType_content_type_contentType
			parts := strings.Split(attackType, "_body_")
			if len(parts) > 1 {
				baseAttackType := parts[0]
				bodyAndContentType := parts[1]
				contentTypeParts := strings.Split(bodyAndContentType, "_content_type_")
				if len(contentTypeParts) > 1 {
					bodyType := contentTypeParts[0]
					contentType := strings.ReplaceAll(contentTypeParts[1], "_", "/")

					payloads := e.mutator.GetPayloadsForType(common.AttackType(baseAttackType))
					for _, p := range payloads {
						if p.Value == payload {
							return p.Variant + "_body_" + bodyType + "_content_type_" + contentType
						}
					}

					// If payload not found, return meaningful variant
					return baseAttackType + "_body_" + bodyType + "_content_type_" + contentType
				}
			}
			return "body_variation_with_content_type"
		}

		// Regular body variation
		parts := strings.Split(attackType, "_body_")
		if len(parts) > 0 {
			baseAttackType := parts[0]
			payloads := e.mutator.GetPayloadsForType(common.AttackType(baseAttackType))

			// Find the payload and return its variant with body suffix
			for _, p := range payloads {
				if p.Value == payload {
					bodyType := parts[1]
					return p.Variant + "_body_" + bodyType
				}
			}

			// If payload not found in base attack type, return a meaningful variant
			bodyType := parts[1]
			return baseAttackType + "_body_" + bodyType
		}
		return "body_variation"
	}

	if strings.Contains(attackType, "_combination_") {
		// Extract base attack type from combination variation
		parts := strings.Split(attackType, "_combination_")
		if len(parts) > 0 {
			baseAttackType := parts[0]
			payloads := e.mutator.GetPayloadsForType(common.AttackType(baseAttackType))

			// Find the payload and return its variant with combination suffix
			for _, p := range payloads {
				if p.Value == payload {
					combinationType := parts[1]
					return p.Variant + "_combination_" + combinationType
				}
			}

			// If payload not found in base attack type, return a meaningful variant
			combinationType := parts[1]
			return baseAttackType + "_combination_" + combinationType
		}
		return "combination_variation"
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

	// If not found, return a default variant name based on attack type
	if e.debug {
		fmt.Printf("🔍 [DEBUG] Variant not found, returning default variant\n")
	}

	// Return a meaningful default variant name
	if strings.Contains(attackType, "_") {
		// For complex attack types, extract the base type
		parts := strings.Split(attackType, "_")
		return parts[0] + "_default"
	}

	return attackType + "_default"
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
		Timestamp:      resp.Timestamp, // Request'in gerçek gönderilme zamanı
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

// hexEncode encodes special characters as hex
func (e *Engine) hexEncode(input string) string {
	var result strings.Builder
	for _, char := range input {
		if char < 32 || char > 126 {
			result.WriteString(fmt.Sprintf("\\x%02x", char))
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// unicodeEncode encodes special characters as unicode
func (e *Engine) unicodeEncode(input string) string {
	var result strings.Builder
	for _, char := range input {
		if char < 32 || char > 126 {
			result.WriteString(fmt.Sprintf("\\u%04x", char))
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// createHeaderVariation creates different header injection patterns
func (e *Engine) createHeaderVariation(headerName, payload string) map[string]string {
	headers := make(map[string]string)

	switch strings.ToLower(headerName) {
	case "user-agent":
		headers["User-Agent"] = payload
	case "referer":
		headers["Referer"] = payload
	case "cookie":
		headers["Cookie"] = payload
	case "accept":
		headers["Accept"] = payload
	case "accept-language":
		headers["Accept-Language"] = payload
	case "accept-encoding":
		headers["Accept-Encoding"] = payload
	case "x-forwarded-for":
		headers["X-Forwarded-For"] = payload
	case "x-forwarded-host":
		headers["X-Forwarded-Host"] = payload
	case "x-original-url":
		headers["X-Original-URL"] = payload
	case "x-rewrite-url":
		headers["X-Rewrite-URL"] = payload
	case "x-custom-ip-authorization":
		headers["X-Custom-IP-Authorization"] = payload
	case "x-forwarded-server":
		headers["X-Forwarded-Server"] = payload
	case "x-http-host-override":
		headers["X-HTTP-Host-Override"] = payload
	case "forwarded":
		headers["Forwarded"] = payload
	default:
		headers[headerName] = payload
	}

	return headers
}

// shouldIncludeVariation checks if a specific variation should be included based on VariationSet
func (e *Engine) shouldIncludeVariation(variationType string, variationSet []string) bool {
	// If no variation set specified, include all variations (default behavior)
	if len(variationSet) == 0 {
		return true
	}

	// Check if the variation type is in the allowed set
	for _, allowedVariation := range variationSet {
		if allowedVariation == variationType {
			return true
		}
	}

	return false
}

// BodyVariationConfig represents configuration for body variations
type BodyVariationConfig struct {
	Fields      map[string]string `json:"fields"`       // Custom field names and values
	Structure   string            `json:"structure"`    // "simple", "nested", "array"
	Template    string            `json:"template"`     // Custom template
	ContentType string            `json:"content_type"` // Custom content type
	Variants    []string          `json:"variants"`     // Content type variants to test
}

// getContentTypeVariants returns different content type variants for testing
func (e *Engine) getContentTypeVariants(baseType string) []string {
	switch baseType {
	case "json":
		return []string{
			"application/json",
			"application/json; charset=utf-8",
			"application/json; charset=UTF-8",
			"application/json; charset=iso-8859-1",
			"application/json; version=1.0",
			"application/json; profile=https://example.com/schema",
			"application/vnd.api+json",
			"application/ld+json",
			"application/geo+json",
		}
	case "form":
		return []string{
			"application/x-www-form-urlencoded",
			"application/x-www-form-urlencoded; charset=utf-8",
			"application/x-www-form-urlencoded; charset=UTF-8",
			"application/x-www-form-urlencoded; charset=iso-8859-1",
		}
	case "xml":
		return []string{
			"application/xml",
			"application/xml; charset=utf-8",
			"application/xml; charset=UTF-8",
			"text/xml",
			"text/xml; charset=utf-8",
			"application/soap+xml",
			"application/atom+xml",
			"application/rss+xml",
		}
	case "multipart":
		return []string{
			"multipart/form-data",
			"multipart/form-data; boundary=----WebKitFormBoundary",
			"multipart/mixed",
			"multipart/alternative",
			"multipart/related",
		}
	default:
		return []string{baseType}
	}
}

// createBodyVariation creates different body types with payload injection
func (e *Engine) createBodyVariation(bodyType, payload string, config *BodyVariationConfig) ([]byte, string) {
	// Use default config if none provided
	if config == nil {
		config = &BodyVariationConfig{
			Fields: map[string]string{
				"id":    "test",
				"name":  "test",
				"email": "test@test.com",
				"data":  "test",
			},
			Structure: "simple",
		}
	}

	// Create body content
	var body []byte
	var contentType string

	switch bodyType {
	case "json":
		// Create JSON body using mutator's logic
		jsonData := map[string]interface{}{
			"id":    payload,
			"name":  payload,
			"email": payload,
			"data":  payload,
		}

		// Override with config fields if provided
		if config.Fields != nil {
			jsonData = make(map[string]interface{})
			for key := range config.Fields {
				jsonData[key] = payload
			}
		}

		// Handle different structures
		if config.Structure == "nested" {
			jsonData = map[string]interface{}{
				"user": map[string]interface{}{
					"id": payload,
					"profile": map[string]interface{}{
						"name":  payload,
						"email": payload,
					},
				},
				"data": payload,
			}
		} else if config.Structure == "array" {
			jsonData = map[string]interface{}{
				"items": []string{payload, payload, payload},
				"data":  payload,
			}
		}

		bodyBytes, _ := json.Marshal(jsonData)
		body = bodyBytes
		contentType = "application/json"

	case "form":
		// Create form body using mutator's logic
		formData := url.Values{}
		formData.Set("id", payload)
		formData.Set("name", payload)
		formData.Set("email", payload)
		formData.Set("data", payload)

		// Override with config fields if provided
		if config.Fields != nil {
			formData = url.Values{}
			for key := range config.Fields {
				formData.Set(key, payload)
			}
		}

		body = []byte(formData.Encode())
		contentType = "application/x-www-form-urlencoded"

	case "xml":
		// Create XML body using mutator's logic
		xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<root>
    <id>%s</id>
    <name>%s</name>
    <email>%s</email>
    <data>%s</data>
</root>`, payload, payload, payload, payload)

		// Override with config fields if provided
		if config.Fields != nil {
			var fieldElements []string
			for key := range config.Fields {
				fieldElements = append(fieldElements, fmt.Sprintf("    <%s>%s</%s>", key, payload, key))
			}
			xmlBody = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<root>
%s
</root>`, strings.Join(fieldElements, "\n"))
		}

		body = []byte(xmlBody)
		contentType = "application/xml"

	case "multipart":
		// Create multipart body using mutator's logic
		boundary := "----WebKitFormBoundary" + fmt.Sprintf("%d", time.Now().Unix())

		var fieldParts []string
		fields := []string{"id", "name", "email", "data"}

		// Override with config fields if provided
		if config.Fields != nil {
			fields = make([]string, 0, len(config.Fields))
			for key := range config.Fields {
				fields = append(fields, key)
			}
		}

		for _, field := range fields {
			fieldPart := fmt.Sprintf(`--%s
Content-Disposition: form-data; name="%s"

%s`, boundary, field, payload)
			fieldParts = append(fieldParts, fieldPart)
		}

		multipartBody := strings.Join(fieldParts, "\n") + "\n--" + boundary + "--"
		body = []byte(multipartBody)
		contentType = "multipart/form-data; boundary=" + boundary

	default:
		// Default to JSON
		jsonData := map[string]interface{}{"data": payload}
		bodyBytes, _ := json.Marshal(jsonData)
		body = bodyBytes
		contentType = "application/json"
	}

	// Override content type if specified in config
	if config.ContentType != "" {
		contentType = config.ContentType
	}

	return body, contentType
}

// createBodyVariationWithVariant creates body with specific content type variant
func (e *Engine) createBodyVariationWithVariant(bodyType, payload string, config *BodyVariationConfig, variant string) ([]byte, string) {
	// Create base body
	body, _ := e.createBodyVariation(bodyType, payload, config)

	// Use specified variant or default
	if variant != "" {
		return body, variant
	}

	// Get default content type
	_, contentType := e.createBodyVariation(bodyType, payload, config)
	return body, contentType
}
