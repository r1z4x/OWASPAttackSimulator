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
	ID             string        `json:"id"`
	RequestID      string        `json:"request_id"`
	ResponseID     string        `json:"response_id"`
	Type           string        `json:"type"`     // "xss", "sqli", "xxe", "ssrf", etc.
	Category       OWASPCategory `json:"category"` // OWASP category
	Severity       Severity      `json:"severity"`
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
}

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

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
	Findings         []Finding          `json:"findings"`
	StartTime        time.Time          `json:"start_time"`
	EndTime          time.Time          `json:"end_time"`
}

// ReportConfig represents configuration for report generation
type ReportConfig struct {
	OutputFormat    string `json:"output_format"` // "markdown", "html", "json"
	OutputFile      string `json:"output_file"`
	IncludeEvidence bool   `json:"include_evidence"`
	GroupBySeverity bool   `json:"group_by_severity"`
}
