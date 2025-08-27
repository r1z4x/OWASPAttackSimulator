package crawl

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/google/uuid"
	"github.com/owaspattacksimulator/internal/common"
	"github.com/owaspattacksimulator/internal/httpx"
)

// Crawler handles web crawling operations
type Crawler struct {
	client *httpx.Client
	store  httpx.RequestStore
}

// NewCrawler creates a new crawler instance
func NewCrawler(client *httpx.Client, store httpx.RequestStore) *Crawler {
	return &Crawler{
		client: client,
		store:  store,
	}
}

// CrawlResult represents the result of a crawl operation
type CrawlResult struct {
	BaseURL   string                   `json:"base_url"`
	Depth     int                      `json:"depth"`
	Requests  []common.RecordedRequest `json:"requests"`
	StartTime time.Time                `json:"start_time"`
	EndTime   time.Time                `json:"end_time"`
}

// Crawl crawls a target URL to discover links and forms
func (c *Crawler) Crawl(baseURL string, depth int) (*CrawlResult, error) {
	startTime := time.Now()

	// Validate base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Create collector
	collector := colly.NewCollector(
		colly.MaxDepth(depth),
		colly.Async(true),
		colly.AllowURLRevisit(),
	)

	// Set up custom transport to use our HTTP client
	collector.WithTransport(&customTransport{client: c.client})

	// Track discovered requests
	var requests []common.RecordedRequest

	// Handle links
	collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		if link != "" {
			absoluteURL := resolveURL(parsedURL, link)
			if absoluteURL != "" {
				collector.Visit(absoluteURL)
			}
		}
	})

	// Handle forms
	collector.OnHTML("form", func(e *colly.HTMLElement) {
		action := e.Attr("action")
		method := strings.ToUpper(e.Attr("method"))
		if method == "" {
			method = "GET"
		}

		formURL := resolveURL(parsedURL, action)
		if formURL == "" {
			formURL = baseURL
		}

		// Create a request for the form
		_, err := http.NewRequest(method, formURL, nil)
		if err != nil {
			return
		}

		// Add form data as query parameters for GET or body for POST
		formData := make(map[string]string)
		e.ForEach("input", func(_ int, input *colly.HTMLElement) {
			name := input.Attr("name")
			value := input.Attr("value")
			if name != "" {
				formData[name] = value
			}
		})

		// Record the form request
		recordedReq := &common.RecordedRequest{
			ID:          generateID(),
			URL:         formURL,
			Method:      method,
			Headers:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:        buildFormBody(formData),
			ContentType: "application/x-www-form-urlencoded",
			Variant:     "form_discovery",
			Timestamp:   time.Now(),
			Source:      "crawl",
		}

		requests = append(requests, *recordedReq)
		if err := c.store.StoreRequest(recordedReq); err != nil {
			fmt.Printf("Failed to store form request: %v\n", err)
		}
	})

	// Start crawling
	if err := collector.Visit(baseURL); err != nil {
		return nil, fmt.Errorf("failed to start crawling: %w", err)
	}

	collector.Wait()

	endTime := time.Now()

	return &CrawlResult{
		BaseURL:   baseURL,
		Depth:     depth,
		Requests:  requests,
		StartTime: startTime,
		EndTime:   endTime,
	}, nil
}

// customTransport wraps our HTTP client for Colly
type customTransport struct {
	client *httpx.Client
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.client.Do(req)
}

// resolveURL resolves relative URLs to absolute URLs
func resolveURL(base *url.URL, href string) string {
	if href == "" {
		return ""
	}

	// Skip javascript: and mailto: links
	if strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return ""
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(parsed)
	return resolved.String()
}

// buildFormBody builds form-encoded body from form data
func buildFormBody(data map[string]string) string {
	if len(data) == 0 {
		return ""
	}

	var pairs []string
	for key, value := range data {
		pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(pairs, "&")
}

// generateID generates a unique ID
func generateID() string {
	return uuid.New().String()
}
