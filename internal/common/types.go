package common

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RecordedRequest represents a captured HTTP request
type RecordedRequest struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	Variant     string            `json:"variant"`
	Timestamp   time.Time         `json:"timestamp"`
	Source      string            `json:"source"` // "crawl" or "har" or "json"
	Raw         string            `json:"raw"`    // Raw HTTP request like Burp Suite
}

// RecordedResponse represents a captured HTTP response
type RecordedResponse struct {
	ID          string            `json:"id"`
	RequestID   string            `json:"request_id"`
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	Duration    time.Duration     `json:"duration"`
	Timestamp   time.Time         `json:"timestamp"`
	Hash        string            `json:"hash"`
	Raw         string            `json:"raw"` // Raw HTTP response like Burp Suite
}

// Finding represents a request-response result
type Finding struct {
	ID             string        `json:"id"`
	RequestID      string        `json:"request_id"`
	ResponseID     string        `json:"response_id"`
	Type           string        `json:"type"`     // "original_request", "mutated_request", "xss", "sqli", etc.
	Category       OWASPCategory `json:"category"` // OWASP category
	Title          string        `json:"title"`
	Description    string        `json:"description"`
	Evidence       string        `json:"evidence"`
	Payload        string        `json:"payload"`
	URL            string        `json:"url"`
	Method         string        `json:"method"`
	ResponseStatus int           `json:"response_status"`
	ResponseSize   int64         `json:"response_size"`
	ResponseTime   time.Duration `json:"response_time"`
	Blocked        bool          `json:"blocked"`      // WAF/IPS blocked
	RateLimited    bool          `json:"rate_limited"` // Rate limiting detected
	Forbidden      bool          `json:"forbidden"`    // 403/401 detected
	ServerError    bool          `json:"server_error"` // 5xx errors
	Timestamp      time.Time     `json:"timestamp"`
	RequestRaw     string        `json:"request_raw"`  // Raw HTTP request
	ResponseRaw    string        `json:"response_raw"` // Raw HTTP response
}

// OWASP Category represents OWASP Top 10 categories
type OWASPCategory string

const (
	OWASPCategoryA01BrokenAccessControl      OWASPCategory = "A01:2021 - Broken Access Control"
	OWASPCategoryA02CryptographicFailures    OWASPCategory = "A02:2021 - Cryptographic Failures"
	OWASPCategoryA03Injection                OWASPCategory = "A03:2021 - Injection"
	OWASPCategoryA04InsecureDesign           OWASPCategory = "A04:2021 - Insecure Design"
	OWASPCategoryA05SecurityMisconfiguration OWASPCategory = "A05:2021 - Security Misconfiguration"
	OWASPCategoryA06VulnerableComponents     OWASPCategory = "A06:2021 - Vulnerable and Outdated Components"
	OWASPCategoryA07AuthFailures             OWASPCategory = "A07:2021 - Identification and Authentication Failures"
	OWASPCategoryA08SoftwareDataIntegrity    OWASPCategory = "A08:2021 - Software and Data Integrity Failures"
	OWASPCategoryA09LoggingFailures          OWASPCategory = "A09:2021 - Security Logging and Monitoring Failures"
	OWASPCategoryA10SSRF                     OWASPCategory = "A10:2021 - Server-Side Request Forgery"
)

// AttackType represents different types of attacks
type AttackType string

const (
	// A01:2021 - Broken Access Control
	AttackBrokenAccessControl AttackType = "broken_access_control"
	AttackIDOR                AttackType = "idor"
	AttackPrivilegeEscalation AttackType = "privilege_escalation"
	AttackJWTManipulation     AttackType = "jwt_manipulation"

	// A02:2021 - Cryptographic Failures
	AttackWeakCrypto        AttackType = "weak_crypto"
	AttackWeakHashing       AttackType = "weak_hashing"
	AttackInsecureTransport AttackType = "insecure_transport"
	AttackWeakRandomness    AttackType = "weak_randomness"

	// A03:2021 - Injection
	AttackXSS               AttackType = "xss"
	AttackSQLi              AttackType = "sqli"
	AttackCommandInj        AttackType = "command_injection"
	AttackLDAPInjection     AttackType = "ldap_injection"
	AttackNoSQLInjection    AttackType = "nosql_injection"
	AttackHeaderInjection   AttackType = "header_injection"
	AttackTemplateInjection AttackType = "template_injection"

	// A04:2021 - Insecure Design
	AttackBusinessLogicFlaw AttackType = "business_logic_flaw"
	AttackRaceCondition     AttackType = "race_condition"
	AttackInsecureWorkflow  AttackType = "insecure_workflow"

	// A05:2021 - Security Misconfiguration
	AttackDefaultCredentials AttackType = "default_credentials"
	AttackDebugMode          AttackType = "debug_mode"
	AttackVerboseErrors      AttackType = "verbose_errors"
	AttackMissingHeaders     AttackType = "missing_headers"
	AttackWeakCORS           AttackType = "weak_cors"

	// A06:2021 - Vulnerable and Outdated Components
	AttackKnownVulnerability AttackType = "known_vulnerability"
	AttackOutdatedComponent  AttackType = "outdated_component"
	AttackVersionDisclosure  AttackType = "version_disclosure"

	// A07:2021 - Identification and Authentication Failures
	AttackWeakAuth        AttackType = "weak_auth"
	AttackSessionFixation AttackType = "session_fixation"
	AttackSessionTimeout  AttackType = "session_timeout"
	AttackWeakPassword    AttackType = "weak_password"
	AttackBruteForce      AttackType = "brute_force"

	// A08:2021 - Software and Data Integrity Failures
	AttackInsecureDeserialization AttackType = "insecure_deserialization"
	AttackCodeInjection           AttackType = "code_injection"
	AttackSupplyChainAttack       AttackType = "supply_chain_attack"

	// A09:2021 - Security Logging and Monitoring Failures
	AttackLogInjection        AttackType = "log_injection"
	AttackLogBypass           AttackType = "log_bypass"
	AttackAuditTrailTampering AttackType = "audit_trail_tampering"

	// A10:2021 - Server-Side Request Forgery
	AttackSSRF         AttackType = "ssrf"
	AttackXXE          AttackType = "xxe"
	AttackOpenRedirect AttackType = "open_redirect"
)

// Payload represents an attack payload
type Payload struct {
	Type    AttackType `json:"type"`
	Value   string     `json:"value"`
	Variant string     `json:"variant"`
}

// CrawlResult represents the result of a crawl operation
type CrawlResult struct {
	BaseURL   string            `json:"base_url"`
	Depth     int               `json:"depth"`
	Requests  []RecordedRequest `json:"requests"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
}

// AttackResult represents the result of an attack operation
type AttackResult struct {
	OriginalRequests []RecordedRequest  `json:"original_requests"`
	MutatedRequests  []RecordedRequest  `json:"mutated_requests"`
	Responses        []RecordedResponse `json:"responses"`
	Findings         []Finding          `json:"findings"` // All request-response results
	StartTime        time.Time          `json:"start_time"`
	EndTime          time.Time          `json:"end_time"`
}

// ReportConfig represents configuration for report generation
type ReportConfig struct {
	OutputFormat    string `json:"output_format"` // "markdown", "html", "json"
	OutputFile      string `json:"output_file"`
	IncludeEvidence bool   `json:"include_evidence"`
}

// GenerateRawRequest generates raw HTTP request format like Burp Suite
func (r *RecordedRequest) GenerateRawRequest() string {
	var raw strings.Builder

	// Parse URL to get path and query
	parsedURL, err := url.Parse(r.URL)
	if err != nil {
		return ""
	}

	// Build request line
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	raw.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", r.Method, path))

	// Add headers
	if host := parsedURL.Host; host != "" {
		raw.WriteString(fmt.Sprintf("Host: %s\n", host))
	}

	for key, value := range r.Headers {
		raw.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	// Add empty line to separate headers from body
	raw.WriteString("\n")

	// Add body if exists
	if r.Body != "" {
		raw.WriteString(r.Body)
	}

	return raw.String()
}

// GenerateRawResponse generates raw HTTP response format like Burp Suite
func (r *RecordedResponse) GenerateRawResponse() string {
	var raw strings.Builder

	// Build status line
	statusText := getStatusText(r.StatusCode)
	raw.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", r.StatusCode, statusText))

	// Add headers
	for key, value := range r.Headers {
		raw.WriteString(fmt.Sprintf("%s: %s\n", key, value))
	}

	// Add empty line to separate headers from body
	raw.WriteString("\n")

	// Add body if exists
	if r.Body != "" {
		raw.WriteString(r.Body)
	}

	return raw.String()
}

// getStatusText returns HTTP status text for status code
func getStatusText(statusCode int) string {
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
