package common

import (
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
}

// Finding represents a security vulnerability finding
type Finding struct {
	ID          string    `json:"id"`
	RequestID   string    `json:"request_id"`
	ResponseID  string    `json:"response_id"`
	Type        string    `json:"type"`        // "xss", "sqli", "xxe", "ssrf", etc.
	Category    string    `json:"category"`    // OWASP category
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Payload     string    `json:"payload"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Timestamp   time.Time `json:"timestamp"`
}

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// AttackType represents different types of attacks
type AttackType string

const (
	AttackXSS           AttackType = "xss"
	AttackSQLi          AttackType = "sqli"
	AttackXXE           AttackType = "xxe"
	AttackSSRF          AttackType = "ssrf"
	AttackCommandInj    AttackType = "command_injection"
	AttackHeaderInj     AttackType = "header_injection"
	AttackMethodOverride AttackType = "method_override"
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
	OriginalRequests []RecordedRequest `json:"original_requests"`
	MutatedRequests  []RecordedRequest `json:"mutated_requests"`
	Responses        []RecordedResponse `json:"responses"`
	Findings         []Finding         `json:"findings"`
	StartTime        time.Time         `json:"start_time"`
	EndTime          time.Time         `json:"end_time"`
}

// ReportConfig represents configuration for report generation
type ReportConfig struct {
	OutputFormat string `json:"output_format"` // "markdown", "html", "json"
	OutputFile   string `json:"output_file"`
	IncludeEvidence bool `json:"include_evidence"`
	GroupBySeverity bool `json:"group_by_severity"`
}
