package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client represents an HTTP client with attack capabilities
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
	userAgent  string
}

// NewClient creates a new HTTP client
func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For testing purposes
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		timeout:   timeout,
		userAgent: "OWASPAttackSimulator/1.0",
	}
}

// Request represents an HTTP request
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Params  map[string]string
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Duration   time.Duration
	URL        string
	Parameter  string // Parameter that was tested
	Payload    string // Payload that was used
	AttackType string // Attack type that was used
}

// DoRequest performs an HTTP request
func (c *Client) DoRequest(ctx context.Context, req *Request) (*Response, error) {
	// Build URL with query parameters
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	// Add query parameters
	if req.Params != nil {
		query := parsedURL.Query()
		for key, value := range req.Params {
			query.Set(key, value)
		}
		parsedURL.RawQuery = query.Encode()
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, parsedURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	httpReq.Header.Set("User-Agent", c.userAgent)
	if req.Headers != nil {
		for key, value := range req.Headers {
			httpReq.Header.Set(key, value)
		}
	}

	// Perform request
	start := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Convert headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
		Duration:   time.Since(start),
		URL:        resp.Request.URL.String(),
	}, nil
}

// AttackRequest represents an attack request with payload
type AttackRequest struct {
	BaseRequest Request
	Payload     string
	Parameter   string
	Type        string // "xss", "sqli", "ssrf", etc.
}

// AttackResponse represents an attack response with vulnerability info
type AttackResponse struct {
	Response   *Response
	Vulnerable bool
	VulnType   string
	Evidence   string
	Payload    string
	Parameter  string
	Confidence float64
}

// PerformAttack performs an attack with the given payload
func (c *Client) PerformAttack(ctx context.Context, attackReq *AttackRequest) (*AttackResponse, error) {
	// Create a deep copy of the base request to avoid concurrent map access
	req := Request{
		Method:  attackReq.BaseRequest.Method,
		URL:     attackReq.BaseRequest.URL,
		Headers: make(map[string]string),
		Params:  make(map[string]string),
	}

	// Copy headers
	for k, v := range attackReq.BaseRequest.Headers {
		req.Headers[k] = v
	}

	// Copy existing params
	for k, v := range attackReq.BaseRequest.Params {
		req.Params[k] = v
	}

	// Inject payload into the appropriate place
	switch attackReq.Type {
	case "xss":
		// Inject into query parameters or body
		req.Params[attackReq.Parameter] = attackReq.Payload
	case "sqli":
		// Inject into query parameters
		req.Params[attackReq.Parameter] = attackReq.Payload
	case "ssrf":
		// Inject into URL or parameters
		req.Params[attackReq.Parameter] = attackReq.Payload
	}

	// Perform the request
	resp, err := c.DoRequest(ctx, &req)
	if err != nil {
		return nil, err
	}

	// Analyze response for vulnerabilities
	vulnInfo := c.analyzeResponse(resp, attackReq)

	return &AttackResponse{
		Response:   resp,
		Vulnerable: vulnInfo.Vulnerable,
		VulnType:   vulnInfo.VulnType,
		Evidence:   vulnInfo.Evidence,
		Payload:    attackReq.Payload,
		Parameter:  attackReq.Parameter,
		Confidence: vulnInfo.Confidence,
	}, nil
}

// VulnerabilityInfo represents vulnerability analysis results
type VulnerabilityInfo struct {
	Vulnerable bool
	VulnType   string
	Evidence   string
	Confidence float64
}

// analyzeResponse analyzes the response for vulnerabilities
func (c *Client) analyzeResponse(resp *Response, attackReq *AttackRequest) *VulnerabilityInfo {
	// Check for XSS reflection
	if attackReq.Type == "xss" {
		if bytes.Contains(resp.Body, []byte(attackReq.Payload)) {
			return &VulnerabilityInfo{
				Vulnerable: true,
				VulnType:   "XSS (Reflected)",
				Evidence:   fmt.Sprintf("Payload reflected in response: %s", attackReq.Payload),
				Confidence: 0.8,
			}
		}
	}

	// Check for SQL injection errors
	if attackReq.Type == "sqli" {
		sqlErrors := []string{
			"sql syntax",
			"mysql_fetch",
			"ORA-",
			"PostgreSQL",
			"SQLite",
			"Microsoft OLE DB",
		}
		for _, err := range sqlErrors {
			if bytes.Contains(bytes.ToLower(resp.Body), []byte(err)) {
				return &VulnerabilityInfo{
					Vulnerable: true,
					VulnType:   "SQL Injection (Error-based)",
					Evidence:   fmt.Sprintf("SQL error detected: %s", err),
					Confidence: 0.9,
				}
			}
		}
	}

	// Check for SSRF indicators
	if attackReq.Type == "ssrf" {
		// This would require more sophisticated analysis
		// For now, just check if the request was successful
		if resp.StatusCode == 200 {
			return &VulnerabilityInfo{
				Vulnerable: true,
				VulnType:   "SSRF (Potential)",
				Evidence:   "Request to external URL was successful",
				Confidence: 0.6,
			}
		}
	}

	return &VulnerabilityInfo{
		Vulnerable: false,
		VulnType:   "",
		Evidence:   "",
		Confidence: 0.0,
	}
}
