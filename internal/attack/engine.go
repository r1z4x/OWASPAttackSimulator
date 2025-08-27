package attack

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owaspattacksimulator/internal/common"
	"github.com/owaspattacksimulator/internal/httpx"
	"github.com/owaspattacksimulator/internal/mutate"
	"github.com/schollz/progressbar/v3"
)

// Engine handles the attack execution
type Engine struct {
	client       *httpx.Client
	mutator      *mutate.Mutator
	store        httpx.RequestStore
	workers      int
	delay        time.Duration
	burst        int
	requestCount int64
	delayMutex   sync.Mutex
	debug        bool
}

// NewEngine creates a new attack engine
func NewEngine(client *httpx.Client, store httpx.RequestStore, workers int, delay int, burst int) *Engine {
	return &Engine{
		client:  client,
		mutator: mutate.NewMutator(),
		store:   store,
		workers: workers,
		delay:   time.Duration(delay) * time.Millisecond,
		burst:   burst,
		debug:   false,
	}
}

// SetDebugMode enables or disables debug mode
func (e *Engine) SetDebugMode(debug bool) {
	e.debug = debug
}

// getStatusText returns a human-readable status text
func getStatusText(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "OK"
	case statusCode >= 300 && statusCode < 400:
		return "Redirect"
	case statusCode >= 400 && statusCode < 500:
		return "Client Error"
	case statusCode >= 500:
		return "Server Error"
	default:
		return "Unknown"
	}
}

// AttackResult represents the result of an attack operation
type AttackResult struct {
	OriginalRequests []common.RecordedRequest  `json:"original_requests"`
	MutatedRequests  []common.RecordedRequest  `json:"mutated_requests"`
	Responses        []common.RecordedResponse `json:"responses"`
	Findings         []common.Finding          `json:"findings"`
	StartTime        time.Time                 `json:"start_time"`
	EndTime          time.Time                 `json:"end_time"`
}

// Attack executes attacks on the provided requests
func (e *Engine) Attack(requests []common.RecordedRequest) (*AttackResult, error) {
	return e.AttackWithProgress(context.Background(), requests, nil)
}

// AttackWithProgress executes attacks with progress tracking
func (e *Engine) AttackWithProgress(ctx context.Context, requests []common.RecordedRequest, bar *progressbar.ProgressBar) (*AttackResult, error) {
	startTime := time.Now()

	var allMutatedRequests []common.RecordedRequest
	var allResponses []common.RecordedResponse
	var allFindings []common.Finding

	// Create a channel for processing requests
	requestChan := make(chan common.RecordedRequest, len(requests))
	resultChan := make(chan attackResult, len(requests))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go e.worker(ctx, &wg, requestChan, resultChan)
	}

	// Send requests to workers
	go func() {
		defer close(requestChan)
		for _, req := range requests {
			requestChan <- req
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results with progress
	processedCount := 0
	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				// Channel closed, all results processed
				goto processComplete
			}
			allMutatedRequests = append(allMutatedRequests, result.mutatedRequests...)
			allResponses = append(allResponses, result.responses...)
			allFindings = append(allFindings, result.findings...)

			processedCount++
			// Only update progress bar if not in debug mode
			if bar != nil && !e.debug {
				bar.Add(1)
			}
		case <-ctx.Done():
			// Context cancelled, stop processing
			fmt.Printf("\n🛑 Attack cancelled by user\n")
			return &AttackResult{
				OriginalRequests: requests,
				MutatedRequests:  allMutatedRequests,
				Responses:        allResponses,
				Findings:         allFindings,
				StartTime:        startTime,
				EndTime:          time.Now(),
			}, ctx.Err()
		}
	}
processComplete:

	// Only finish progress bar if not in debug mode
	if bar != nil && !e.debug {
		bar.Finish()
	}

	endTime := time.Now()

	return &AttackResult{
		OriginalRequests: requests,
		MutatedRequests:  allMutatedRequests,
		Responses:        allResponses,
		Findings:         allFindings,
		StartTime:        startTime,
		EndTime:          endTime,
	}, nil
}

// attackResult represents the result of attacking a single request
type attackResult struct {
	mutatedRequests []common.RecordedRequest
	responses       []common.RecordedResponse
	findings        []common.Finding
}

// worker processes requests in a goroutine
func (e *Engine) worker(ctx context.Context, wg *sync.WaitGroup, requestChan <-chan common.RecordedRequest, resultChan chan<- attackResult) {
	defer wg.Done()

	for {
		select {
		case req, ok := <-requestChan:
			if !ok {
				// Channel closed, exit
				return
			}
			// Check if we need to apply delay
			e.checkAndApplyDelay()

			result := e.attackRequest(&req)
			select {
			case resultChan <- result:
				// Result sent successfully
			case <-ctx.Done():
				// Context cancelled, exit
				return
			}
		case <-ctx.Done():
			// Context cancelled, exit
			return
		}
	}
}

// checkAndApplyDelay checks if delay should be applied and applies it
func (e *Engine) checkAndApplyDelay() {
	if e.delay <= 0 {
		return
	}

	e.delayMutex.Lock()
	defer e.delayMutex.Unlock()

	e.requestCount++

	// If workers is 1, apply delay after every request
	// Otherwise, apply delay after every burst of requests
	if e.workers == 1 {
		if e.debug {
			fmt.Printf("Applied delay of %v after request %d (single thread mode)\n", e.delay, e.requestCount)
		}
		time.Sleep(e.delay)
	} else if e.burst > 0 && e.requestCount%int64(e.burst) == 0 {
		if e.debug {
			fmt.Printf("Applied delay of %v after %d requests (burst mode)\n", e.delay, e.burst)
		}
		time.Sleep(e.delay)
	}
}

// attackRequest attacks a single request
func (e *Engine) attackRequest(req *common.RecordedRequest) attackResult {
	var mutatedRequests []common.RecordedRequest
	var responses []common.RecordedResponse
	var findings []common.Finding

	// Generate mutations
	mutations, err := e.mutator.MutateRequest(req)
	if err != nil {
		fmt.Printf("Failed to mutate request %s: %v\n", req.ID, err)
		return attackResult{}
	}

	mutatedRequests = append(mutatedRequests, mutations...)

	// Send original request
	if e.debug {
		fmt.Printf("\n🔍 [DEBUG] Testing original request: %s %s\n", req.Method, req.URL)
		if len(req.Headers) > 0 {
			fmt.Printf("   Headers: %v\n", req.Headers)
		}
		fmt.Printf("   Body: %s\n", req.Body)
	} else {
		fmt.Printf("🔍 Testing original request: %s %s\n", req.Method, req.URL)
		fmt.Printf("   Body: %s\n", req.Body)
	}

	originalResp, err := e.sendRequest(req)
	if err != nil {
		fmt.Printf("Failed to send original request %s: %v\n", req.ID, err)
	} else {
		responses = append(responses, *originalResp)

		// Show response details in debug mode
		if e.debug {
			fmt.Printf("   📡 [DEBUG] Response: %d %s (Size: %d bytes, Duration: %v)\n",
				originalResp.StatusCode, getStatusText(originalResp.StatusCode), originalResp.Size, originalResp.Duration)
			if len(originalResp.Headers) > 0 {
				fmt.Printf("   Response Headers: %v\n", originalResp.Headers)
			}
			if originalResp.Body != "" {
				fmt.Printf("   Response Body: %s\n", originalResp.Body)
			}
		}

		// Create finding for original request (every request gets a finding)
		originalFinding := e.createFindingFromRequest(req, originalResp, "original_request")
		findings = append(findings, originalFinding)

	}

	// Send mutated requests
	for _, mutation := range mutations {
		if e.debug {
			fmt.Printf("\n🚀 [DEBUG] Testing mutation: %s %s\n", mutation.Method, mutation.URL)
			if len(mutation.Headers) > 0 {
				fmt.Printf("   Headers: %v\n", mutation.Headers)
			}
			fmt.Printf("   Body: %s\n", mutation.Body)
		} else {
			fmt.Printf("🚀 Testing mutation: %s %s (Payload: %s)\n", mutation.Method, mutation.URL, mutation.Body)
		}

		resp, err := e.sendRequest(&mutation)
		if err != nil {
			fmt.Printf("Failed to send mutated request %s: %v\n", mutation.ID, err)
			continue
		}

		responses = append(responses, *resp)

		// Show response details in debug mode
		if e.debug {
			fmt.Printf("   📡 [DEBUG] Response: %d %s (Size: %d bytes, Duration: %v)\n",
				resp.StatusCode, getStatusText(resp.StatusCode), resp.Size, resp.Duration)
			if len(resp.Headers) > 0 {
				fmt.Printf("   Response Headers: %v\n", resp.Headers)
			}
			if resp.Body != "" {
				fmt.Printf("   Response Body: %s\n", resp.Body)
			}
		}

		// Create finding for mutated request (every request gets a finding)
		mutationFinding := e.createFindingFromRequest(&mutation, resp, "mutated_request")
		findings = append(findings, mutationFinding)
	}

	return attackResult{
		mutatedRequests: mutatedRequests,
		responses:       responses,
		findings:        findings,
	}
}

// sendRequest sends a single HTTP request
func (e *Engine) sendRequest(req *common.RecordedRequest) (*common.RecordedResponse, error) {
	// Create HTTP request
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		// Create error response
		duration := time.Since(time.Now()) // This will be very small
		return &common.RecordedResponse{
			ID:          generateID(),
			RequestID:   req.ID,
			StatusCode:  0,
			Headers:     make(map[string]string),
			Body:        fmt.Sprintf("Request creation failed: %v", err),
			ContentType: "text/plain",
			Size:        0,
			Duration:    duration,
			Timestamp:   time.Now(),
			Hash:        "",
		}, nil
	}

	// Add headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Record start time for accurate duration measurement
	startTime := time.Now()

	// Send request using our HTTP client
	resp, err := e.client.Do(httpReq)
	if err != nil {
		// Create error response with duration
		duration := time.Since(startTime)
		return &common.RecordedResponse{
			ID:          generateID(),
			RequestID:   req.ID,
			StatusCode:  0,
			Headers:     make(map[string]string),
			Body:        fmt.Sprintf("Request failed: %v", err),
			ContentType: "text/plain",
			Size:        0,
			Duration:    duration,
			Timestamp:   time.Now(),
			Hash:        "",
		}, nil
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		// Create error response with duration
		duration := time.Since(startTime)
		return &common.RecordedResponse{
			ID:          generateID(),
			RequestID:   req.ID,
			StatusCode:  resp.StatusCode,
			Headers:     headersToMap(resp.Header),
			Body:        fmt.Sprintf("Failed to read response body: %v", err),
			ContentType: resp.Header.Get("Content-Type"),
			Size:        0,
			Duration:    duration,
			Timestamp:   time.Now(),
			Hash:        "",
		}, nil
	}

	// Calculate actual duration
	duration := time.Since(startTime)

	// Create recorded response
	recordedResp := &common.RecordedResponse{
		ID:          generateID(),
		RequestID:   req.ID,
		StatusCode:  resp.StatusCode,
		Headers:     headersToMap(resp.Header),
		Body:        string(bodyBytes),
		ContentType: resp.Header.Get("Content-Type"),
		Size:        int64(len(bodyBytes)),
		Duration:    duration,
		Timestamp:   time.Now(),
		Hash:        generateHash(bodyBytes),
	}

	// Generate raw HTTP response format
	recordedResp.Raw = recordedResp.GenerateRawResponse()

	return recordedResp, nil
}

// headersToMap converts http.Header to map[string]string
func headersToMap(header http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range header {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

// generateID generates a unique ID
func generateID() string {
	return uuid.New().String()
}

// generateHash generates SHA256 hash of data
func generateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// createFindingFromRequest creates a finding from a request and response
func (e *Engine) createFindingFromRequest(req *common.RecordedRequest, resp *common.RecordedResponse, requestType string) common.Finding {

	// Determine if request was blocked or rate limited
	blocked := e.isRequestBlocked(resp)
	rateLimited := e.isRequestRateLimited(resp)

	// Create finding title and description
	title := fmt.Sprintf("%s Request - %s %s", strings.Title(requestType), req.Method, req.URL)
	description := fmt.Sprintf("Request completed with status %d. Response size: %d bytes, Duration: %v",
		resp.StatusCode, resp.Size, resp.Duration)

	// Extract evidence from response
	evidence := e.extractEvidenceFromResponse(resp)

	// Determine OWASP category based on request type and response
	category := e.determineOWASPCategory(req, resp, requestType)

	return common.Finding{
		ID:         generateID(),
		RequestID:  req.ID,
		ResponseID: resp.ID,
		Type:       requestType,
		Category:   category,

		Title:          title,
		Description:    description,
		Evidence:       evidence,
		Payload:        req.Body,
		URL:            req.URL,
		Method:         req.Method,
		ResponseStatus: resp.StatusCode,
		ResponseSize:   resp.Size,
		ResponseTime:   resp.Duration,
		Blocked:        blocked,
		RateLimited:    rateLimited,
		Forbidden:      resp.StatusCode == 403 || resp.StatusCode == 401,
		ServerError:    resp.StatusCode >= 500,
		Timestamp:      resp.Timestamp,
		RequestRaw:     req.Raw,
		ResponseRaw:    resp.Raw,
	}
}

// isRequestBlocked checks if request was blocked by WAF/IPS
func (e *Engine) isRequestBlocked(resp *common.RecordedResponse) bool {
	// Check for common WAF/IPS indicators
	blockedHeaders := []string{
		"X-WAF-Status", "X-Security", "X-Blocked", "X-Protection",
		"CF-Ray", "X-Cloudflare", "X-Akamai", "X-Fastly",
	}

	for _, header := range blockedHeaders {
		if _, exists := resp.Headers[header]; exists {
			return true
		}
	}

	// Check response body for blocking indicators
	body := strings.ToLower(resp.Body)
	blockedPatterns := []string{
		"access denied", "blocked", "forbidden", "security violation",
		"waf", "firewall", "protection", "threat detected",
	}

	for _, pattern := range blockedPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// isRequestRateLimited checks if request was rate limited
func (e *Engine) isRequestRateLimited(resp *common.RecordedResponse) bool {
	// Check for rate limiting indicators
	rateLimitHeaders := []string{
		"X-RateLimit-Status", "X-RateLimit-Remaining", "X-RateLimit-Reset",
		"Retry-After", "X-RateLimit-Limit",
	}

	for _, header := range rateLimitHeaders {
		if _, exists := resp.Headers[header]; exists {
			return true
		}
	}

	// Check status code
	if resp.StatusCode == 429 {
		return true
	}

	// Check response body for rate limiting indicators
	body := strings.ToLower(resp.Body)
	rateLimitPatterns := []string{
		"rate limit", "too many requests", "throttled", "quota exceeded",
		"try again later", "slow down",
	}

	for _, pattern := range rateLimitPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// extractEvidenceFromResponse extracts evidence from response
func (e *Engine) extractEvidenceFromResponse(resp *common.RecordedResponse) string {
	var evidence []string

	// Add status code evidence
	evidence = append(evidence, fmt.Sprintf("Status: %d", resp.StatusCode))

	// Add size evidence
	evidence = append(evidence, fmt.Sprintf("Size: %d bytes", resp.Size))

	// Add duration evidence
	evidence = append(evidence, fmt.Sprintf("Duration: %v", resp.Duration))

	// Add security headers evidence
	securityHeaders := []string{
		"X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
		"Strict-Transport-Security", "Content-Security-Policy",
		"Referrer-Policy", "Permissions-Policy",
	}

	for _, header := range securityHeaders {
		if value, exists := resp.Headers[header]; exists {
			evidence = append(evidence, fmt.Sprintf("%s: %s", header, value))
		}
	}

	// Add blocking evidence
	if e.isRequestBlocked(resp) {
		evidence = append(evidence, "WAF/IPS Blocked: true")
	}

	// Add rate limiting evidence
	if e.isRequestRateLimited(resp) {
		evidence = append(evidence, "Rate Limited: true")
	}

	return strings.Join(evidence, "; ")
}

// determineOWASPCategory determines OWASP category based on request and response
func (e *Engine) determineOWASPCategory(req *common.RecordedRequest, resp *common.RecordedResponse, requestType string) common.OWASPCategory {
	// For original requests, categorize based on response behavior
	if requestType == "original_request" {
		if resp.StatusCode >= 500 {
			return common.OWASPCategoryA05SecurityMisconfiguration // Server errors
		}
		if resp.StatusCode == 403 || resp.StatusCode == 401 {
			return common.OWASPCategoryA01BrokenAccessControl // Access control
		}
		if e.isRequestBlocked(resp) {
			return common.OWASPCategoryA05SecurityMisconfiguration // Security headers/misconfig
		}
		return common.OWASPCategoryA05SecurityMisconfiguration // General security analysis
	}

	// For mutated requests, categorize based on attack type
	// This will be overridden by the checker if vulnerabilities are found
	return common.OWASPCategoryA03Injection // Default for attack attempts
}
