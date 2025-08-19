package har

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/owaspchecker/internal/common"
)

// HAR represents the HAR file structure
type HAR struct {
	Log Log `json:"log"`
}

// Log represents the log section of HAR
type Log struct {
	Entries []Entry `json:"entries"`
}

// Entry represents a single HAR entry
type Entry struct {
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	StartedDateTime string   `json:"startedDateTime"`
}

// Request represents a HAR request
type Request struct {
	Method      string        `json:"method"`
	URL         string        `json:"url"`
	Headers     []Header      `json:"headers"`
	QueryString []QueryString `json:"queryString"`
	PostData    *PostData     `json:"postData"`
}

// Response represents a HAR response
type Response struct {
	Status  int      `json:"status"`
	Headers []Header `json:"headers"`
	Content Content  `json:"content"`
}

// Header represents a HAR header
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// QueryString represents a HAR query string parameter
type QueryString struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PostData represents HAR post data
type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// Content represents HAR content
type Content struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// Loader handles loading requests from HAR and JSON files
type Loader struct{}

// NewLoader creates a new loader instance
func NewLoader() *Loader {
	return &Loader{}
}

// LoadHAR loads requests from a HAR file
func (l *Loader) LoadHAR(reader io.Reader) ([]common.RecordedRequest, error) {
	var har HAR
	if err := json.NewDecoder(reader).Decode(&har); err != nil {
		return nil, fmt.Errorf("failed to decode HAR: %w", err)
	}

	var requests []common.RecordedRequest
	for _, entry := range har.Log.Entries {
		req, err := l.convertHAREntryToRequest(entry)
		if err != nil {
			continue // Skip invalid entries
		}
		requests = append(requests, *req)
	}

	return requests, nil
}

// LoadJSON loads requests from a JSON file
func (l *Loader) LoadJSON(reader io.Reader) ([]common.RecordedRequest, error) {
	var requests []common.RecordedRequest
	if err := json.NewDecoder(reader).Decode(&requests); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	return requests, nil
}

// convertHAREntryToRequest converts a HAR entry to a RecordedRequest
func (l *Loader) convertHAREntryToRequest(entry Entry) (*common.RecordedRequest, error) {
	// Parse the started date time
	startedTime, err := time.Parse(time.RFC3339, entry.StartedDateTime)
	if err != nil {
		startedTime = time.Now()
	}

	// Build URL with query parameters
	reqURL := entry.Request.URL
	if len(entry.Request.QueryString) > 0 {
		parsedURL, err := url.Parse(reqURL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %w", err)
		}

		query := parsedURL.Query()
		for _, param := range entry.Request.QueryString {
			query.Set(param.Name, param.Value)
		}
		parsedURL.RawQuery = query.Encode()
		reqURL = parsedURL.String()
	}

	// Convert headers
	headers := make(map[string]string)
	for _, header := range entry.Request.Headers {
		headers[header.Name] = header.Value
	}

	// Determine content type and body
	contentType := "application/x-www-form-urlencoded"
	body := ""

	if entry.Request.PostData != nil {
		contentType = entry.Request.PostData.MimeType
		body = entry.Request.PostData.Text
	}

	return &common.RecordedRequest{
		ID:          generateID(),
		URL:         reqURL,
		Method:      strings.ToUpper(entry.Request.Method),
		Headers:     headers,
		Body:        body,
		ContentType: contentType,
		Variant:     "har_import",
		Timestamp:   startedTime,
		Source:      "har",
	}, nil
}

// generateID generates a unique ID
func generateID() string {
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), time.Now().UnixNano()%1000)
}
