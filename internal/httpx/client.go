package httpx

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/owaspattacksimulator/internal/common"
)

// Client wraps http.Client with request/response logging
type Client struct {
	httpClient *http.Client
	store      RequestStore
}

// RequestStore interface for storing requests and responses
type RequestStore interface {
	StoreRequest(req *common.RecordedRequest) error
	StoreResponse(resp *common.RecordedResponse) error
}

// NewClient creates a new HTTP client with logging
func NewClient(store RequestStore) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		store: store,
	}
}

// Do executes an HTTP request and logs both request and response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	startTime := time.Now()

	// Record the request
	recordedReq := &common.RecordedRequest{
		ID:          generateID(),
		URL:         req.URL.String(),
		Method:      req.Method,
		Headers:     headersToMap(req.Header),
		ContentType: req.Header.Get("Content-Type"),
		Timestamp:   startTime,
		Source:      "httpx",
	}

	// Read and record request body
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		recordedReq.Body = string(bodyBytes)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Store the request
	if err := c.store.StoreRequest(recordedReq); err != nil {
		return nil, fmt.Errorf("failed to store request: %w", err)
	}

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Record the response
	duration := time.Since(startTime)
	recordedResp := &common.RecordedResponse{
		ID:          generateID(),
		RequestID:   recordedReq.ID,
		StatusCode:  resp.StatusCode,
		Headers:     headersToMap(resp.Header),
		ContentType: resp.Header.Get("Content-Type"),
		Duration:    duration,
		Timestamp:   time.Now(),
	}

	// Read and record response body
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		recordedResp.Body = string(bodyBytes)
		recordedResp.Size = int64(len(bodyBytes))
		recordedResp.Hash = generateHash(bodyBytes)
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Store the response
	if err := c.store.StoreResponse(recordedResp); err != nil {
		return nil, fmt.Errorf("failed to store response: %w", err)
	}

	return resp, nil
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

// generateID generates a unique ID for requests/responses
func generateID() string {
	return uuid.New().String()
}

// generateHash generates SHA256 hash of data
func generateHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}
