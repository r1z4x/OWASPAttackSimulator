package attack

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owaspchecker/internal/checks"
	"github.com/owaspchecker/internal/common"
	"github.com/owaspchecker/internal/httpx"
	"github.com/owaspchecker/internal/mutate"
	"github.com/schollz/progressbar/v3"
)

// Engine handles the attack execution
type Engine struct {
	client       *httpx.Client
	mutator      *mutate.Mutator
	checker      *checks.Checker
	store        httpx.RequestStore
	concurrency  int
	delay        time.Duration
	burst        int
	requestCount int64
	delayMutex   sync.Mutex
}

// NewEngine creates a new attack engine
func NewEngine(client *httpx.Client, store httpx.RequestStore, concurrency int, delay int, burst int) *Engine {
	return &Engine{
		client:      client,
		mutator:     mutate.NewMutator(),
		checker:     checks.NewChecker(),
		store:       store,
		concurrency: concurrency,
		delay:       time.Duration(delay) * time.Millisecond,
		burst:       burst,
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
	return e.AttackWithProgress(requests, nil)
}

// AttackWithProgress executes attacks with progress tracking
func (e *Engine) AttackWithProgress(requests []common.RecordedRequest, bar *progressbar.ProgressBar) (*AttackResult, error) {
	startTime := time.Now()

	var allMutatedRequests []common.RecordedRequest
	var allResponses []common.RecordedResponse
	var allFindings []common.Finding

	// Create a channel for processing requests
	requestChan := make(chan common.RecordedRequest, len(requests))
	resultChan := make(chan attackResult, len(requests))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < e.concurrency; i++ {
		wg.Add(1)
		go e.worker(&wg, requestChan, resultChan)
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
	for result := range resultChan {
		allMutatedRequests = append(allMutatedRequests, result.mutatedRequests...)
		allResponses = append(allResponses, result.responses...)
		allFindings = append(allFindings, result.findings...)

		processedCount++
		if bar != nil {
			bar.Add(1)
		}
	}

	if bar != nil {
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
func (e *Engine) worker(wg *sync.WaitGroup, requestChan <-chan common.RecordedRequest, resultChan chan<- attackResult) {
	defer wg.Done()

	for req := range requestChan {
		// Check if we need to apply delay
		e.checkAndApplyDelay()

		result := e.attackRequest(&req)
		resultChan <- result
	}
}

// checkAndApplyDelay checks if delay should be applied and applies it
func (e *Engine) checkAndApplyDelay() {
	if e.delay <= 0 || e.burst <= 0 {
		return
	}

	e.delayMutex.Lock()
	defer e.delayMutex.Unlock()

	e.requestCount++
	if e.requestCount%int64(e.burst) == 0 {
		fmt.Printf("Applied delay of %v after %d requests\n", e.delay, e.burst)
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
	originalResp, err := e.sendRequest(req)
	if err != nil {
		fmt.Printf("Failed to send original request %s: %v\n", req.ID, err)
	} else {
		responses = append(responses, *originalResp)

		// Check for vulnerabilities in original response
		originalFindings := e.checker.CheckResponse(req, originalResp)
		findings = append(findings, originalFindings...)
	}

	// Send mutated requests
	for _, mutation := range mutations {
		resp, err := e.sendRequest(&mutation)
		if err != nil {
			fmt.Printf("Failed to send mutated request %s: %v\n", mutation.ID, err)
			continue
		}

		responses = append(responses, *resp)

		// Check for vulnerabilities in mutated response
		mutationFindings := e.checker.CheckResponse(&mutation, resp)
		findings = append(findings, mutationFindings...)
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
