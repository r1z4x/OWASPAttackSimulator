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
	Method     string // HTTP method used
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
		Method:     req.Method,
	}, nil
}
