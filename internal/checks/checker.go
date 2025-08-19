package checks

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/owaspchecker/internal/common"
)

// Checker handles vulnerability detection
type Checker struct {
	patterns map[common.AttackType][]*regexp.Regexp
}

// NewChecker creates a new checker instance
func NewChecker() *Checker {
	c := &Checker{
		patterns: make(map[common.AttackType][]*regexp.Regexp),
	}
	c.initPatterns()
	return c
}

// initPatterns initializes detection patterns
func (c *Checker) initPatterns() {
	// XSS reflection patterns
	c.patterns[common.AttackXSS] = []*regexp.Regexp{
		regexp.MustCompile(`<script[^>]*>.*?</script>`),
		regexp.MustCompile(`javascript:`),
		regexp.MustCompile(`on\w+\s*=`),
		regexp.MustCompile(`<img[^>]*onerror`),
		regexp.MustCompile(`<svg[^>]*onload`),
	}

	// SQL Injection error patterns
	c.patterns[common.AttackSQLi] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)sql syntax.*mysql`),
		regexp.MustCompile(`(?i)warning.*mysql`),
		regexp.MustCompile(`(?i)mysql.*error`),
		regexp.MustCompile(`(?i)sql syntax.*maria`),
		regexp.MustCompile(`(?i)oracle.*error`),
		regexp.MustCompile(`(?i)postgresql.*error`),
		regexp.MustCompile(`(?i)sql server.*error`),
		regexp.MustCompile(`(?i)sqlite.*error`),
		regexp.MustCompile(`(?i)sql.*syntax`),
		regexp.MustCompile(`(?i)unclosed quotation mark`),
		regexp.MustCompile(`(?i)quoted string not properly terminated`),
	}

	// XXE patterns
	c.patterns[common.AttackXXE] = []*regexp.Regexp{
		regexp.MustCompile(`root:.*:0:0:`),
		regexp.MustCompile(`<!DOCTYPE.*\[.*<!ENTITY.*SYSTEM`),
		regexp.MustCompile(`xmlns:xi="http://www.w3.org/2001/XInclude"`),
	}

	// SSRF patterns
	c.patterns[common.AttackSSRF] = []*regexp.Regexp{
		regexp.MustCompile(`127\.0\.0\.1`),
		regexp.MustCompile(`localhost`),
		regexp.MustCompile(`169\.254\.169\.254`),
		regexp.MustCompile(`metadata\.google\.internal`),
		regexp.MustCompile(`169\.254\.170\.2`),
	}
}

// CheckResponse checks a response for vulnerabilities
func (c *Checker) CheckResponse(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for XSS reflection
	xssFindings := c.checkXSS(req, resp)
	findings = append(findings, xssFindings...)

	// Check for SQL injection errors
	sqliFindings := c.checkSQLi(req, resp)
	findings = append(findings, sqliFindings...)

	// Check for XXE
	xxeFindings := c.checkXXE(req, resp)
	findings = append(findings, xxeFindings...)

	// Check for SSRF
	ssrfFindings := c.checkSSRF(req, resp)
	findings = append(findings, ssrfFindings...)

	// Check for header misconfigurations
	headerFindings := c.checkHeaders(req, resp)
	findings = append(findings, headerFindings...)

	return findings
}

// checkXSS checks for XSS vulnerabilities
func (c *Checker) checkXSS(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check if payload is reflected in response
	for _, pattern := range c.patterns[common.AttackXSS] {
		if pattern.MatchString(resp.Body) {
			// Check if the payload from request is reflected
			if strings.Contains(resp.Body, extractPayload(req)) {
				finding := common.Finding{
					ID:          generateID(),
					RequestID:   req.ID,
					ResponseID:  resp.ID,
					Type:        string(common.AttackXSS),
					Category:    "A03:2021 - Injection",
					Severity:    common.SeverityHigh,
					Title:       "Cross-Site Scripting (XSS) - Reflected",
					Description: "XSS payload was reflected in the response without proper encoding",
					Evidence:    extractEvidence(resp.Body, extractPayload(req)),
					Payload:     extractPayload(req),
					URL:         req.URL,
					Method:      req.Method,
					Timestamp:   time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkSQLi checks for SQL injection vulnerabilities
func (c *Checker) checkSQLi(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	for _, pattern := range c.patterns[common.AttackSQLi] {
		if pattern.MatchString(resp.Body) {
			finding := common.Finding{
				ID:          generateID(),
				RequestID:   req.ID,
				ResponseID:  resp.ID,
				Type:        string(common.AttackSQLi),
				Category:    "A03:2021 - Injection",
				Severity:    common.SeverityCritical,
				Title:       "SQL Injection - Error Based",
				Description: "SQL injection error detected in response",
				Evidence:    extractEvidence(resp.Body, pattern.String()),
				Payload:     extractPayload(req),
				URL:         req.URL,
				Method:      req.Method,
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkXXE checks for XXE vulnerabilities
func (c *Checker) checkXXE(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	for _, pattern := range c.patterns[common.AttackXXE] {
		if pattern.MatchString(resp.Body) {
			finding := common.Finding{
				ID:          generateID(),
				RequestID:   req.ID,
				ResponseID:  resp.ID,
				Type:        string(common.AttackXXE),
				Category:    "A05:2021 - Security Misconfiguration",
				Severity:    common.SeverityCritical,
				Title:       "XML External Entity (XXE) Injection",
				Description: "XXE vulnerability detected in response",
				Evidence:    extractEvidence(resp.Body, pattern.String()),
				Payload:     extractPayload(req),
				URL:         req.URL,
				Method:      req.Method,
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkSSRF checks for SSRF vulnerabilities
func (c *Checker) checkSSRF(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	for _, pattern := range c.patterns[common.AttackSSRF] {
		if pattern.MatchString(resp.Body) {
			finding := common.Finding{
				ID:          generateID(),
				RequestID:   req.ID,
				ResponseID:  resp.ID,
				Type:        string(common.AttackSSRF),
				Category:    "A10:2021 - Server-Side Request Forgery",
				Severity:    common.SeverityHigh,
				Title:       "Server-Side Request Forgery (SSRF)",
				Description: "SSRF vulnerability detected in response",
				Evidence:    extractEvidence(resp.Body, pattern.String()),
				Payload:     extractPayload(req),
				URL:         req.URL,
				Method:      req.Method,
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkHeaders checks for security header misconfigurations
func (c *Checker) checkHeaders(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for missing security headers
	securityHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy": "default-src 'self'",
	}

	for header, expectedValue := range securityHeaders {
		if value, exists := resp.Headers[header]; !exists {
			finding := common.Finding{
				ID:          generateID(),
				RequestID:   req.ID,
				ResponseID:  resp.ID,
				Type:        "missing_security_header",
				Category:    "A05:2021 - Security Misconfiguration",
				Severity:    common.SeverityMedium,
				Title:       fmt.Sprintf("Missing Security Header: %s", header),
				Description: fmt.Sprintf("Security header %s is missing from response", header),
				Evidence:    fmt.Sprintf("Header %s not found in response headers", header),
				Payload:     "",
				URL:         req.URL,
				Method:      req.Method,
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		} else if value != expectedValue {
			finding := common.Finding{
				ID:          generateID(),
				RequestID:   req.ID,
				ResponseID:  resp.ID,
				Type:        "weak_security_header",
				Category:    "A05:2021 - Security Misconfiguration",
				Severity:    common.SeverityLow,
				Title:       fmt.Sprintf("Weak Security Header: %s", header),
				Description: fmt.Sprintf("Security header %s has weak value: %s", header, value),
				Evidence:    fmt.Sprintf("Header %s = %s (expected: %s)", header, value, expectedValue),
				Payload:     "",
				URL:         req.URL,
				Method:      req.Method,
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// extractPayload extracts the payload from a request
func extractPayload(req *common.RecordedRequest) string {
	// Look for common payload patterns in the request
	payloadPatterns := []string{
		"<script>alert(1)</script>",
		"' OR '1'='1",
		"<!DOCTYPE foo",
		"127.0.0.1",
		"javascript:",
	}

	for _, pattern := range payloadPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			return pattern
		}
	}

	return ""
}

// extractEvidence extracts evidence from response body
func extractEvidence(body, pattern string) string {
	// Find the line containing the pattern
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.Contains(line, pattern) {
			return strings.TrimSpace(line)
		}
	}
	return pattern
}

// generateID generates a unique ID
func generateID() string {
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), time.Now().UnixNano()%1000)
}
