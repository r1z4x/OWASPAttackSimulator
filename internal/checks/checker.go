package checks

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
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

// CheckResponse analyzes response behavior for all attack types
func (c *Checker) CheckResponse(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Always analyze general response behavior first
	generalFindings := c.analyzeGeneralResponse(req, resp)
	findings = append(findings, generalFindings...)

	// Extract attack type from request variant or payload
	attackType := c.extractAttackType(req)
	if attackType != "" {
		// Analyze response behavior for specific attack type
		finding := c.analyzeAttackResponse(req, resp, attackType)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// extractAttackType extracts attack type from request
func (c *Checker) extractAttackType(req *common.RecordedRequest) string {
	// Check variant first - look for specific attack type patterns
	if req.Variant != "" {
		variant := strings.ToLower(req.Variant)

		// Map variant patterns to attack types
		if strings.Contains(variant, "xss") {
			return string(common.AttackXSS)
		}
		if strings.Contains(variant, "sqli") || strings.Contains(variant, "sql") {
			return string(common.AttackSQLi)
		}
		if strings.Contains(variant, "command") || strings.Contains(variant, "cmd") {
			return string(common.AttackCommandInj)
		}
		if strings.Contains(variant, "ssrf") {
			return string(common.AttackSSRF)
		}
		if strings.Contains(variant, "xxe") {
			return string(common.AttackXXE)
		}
		if strings.Contains(variant, "ldap") {
			return string(common.AttackLDAPInjection)
		}
		if strings.Contains(variant, "nosql") {
			return string(common.AttackNoSQLInjection)
		}
		if strings.Contains(variant, "header") {
			return string(common.AttackHeaderInjection)
		}
		if strings.Contains(variant, "template") {
			return string(common.AttackTemplateInjection)
		}
		if strings.Contains(variant, "access") || strings.Contains(variant, "admin") {
			return string(common.AttackBrokenAccessControl)
		}
		if strings.Contains(variant, "idor") {
			return string(common.AttackIDOR)
		}
		if strings.Contains(variant, "privilege") || strings.Contains(variant, "escalation") {
			return string(common.AttackPrivilegeEscalation)
		}
		if strings.Contains(variant, "jwt") {
			return string(common.AttackJWTManipulation)
		}
		if strings.Contains(variant, "crypto") || strings.Contains(variant, "hash") {
			return string(common.AttackWeakCrypto)
		}
		if strings.Contains(variant, "transport") {
			return string(common.AttackInsecureTransport)
		}
		if strings.Contains(variant, "logic") || strings.Contains(variant, "business") {
			return string(common.AttackBusinessLogicFlaw)
		}
		if strings.Contains(variant, "race") {
			return string(common.AttackRaceCondition)
		}
		if strings.Contains(variant, "credential") || strings.Contains(variant, "default") {
			return string(common.AttackDefaultCredentials)
		}
		if strings.Contains(variant, "debug") {
			return string(common.AttackDebugMode)
		}
		if strings.Contains(variant, "verbose") || strings.Contains(variant, "error") {
			return string(common.AttackVerboseErrors)
		}
		if strings.Contains(variant, "header") || strings.Contains(variant, "cors") {
			return string(common.AttackMissingHeaders)
		}
		if strings.Contains(variant, "cors") {
			return string(common.AttackWeakCORS)
		}
		if strings.Contains(variant, "vulnerability") || strings.Contains(variant, "component") {
			return string(common.AttackKnownVulnerability)
		}
		if strings.Contains(variant, "outdated") || strings.Contains(variant, "version") {
			return string(common.AttackOutdatedComponent)
		}
		if strings.Contains(variant, "auth") || strings.Contains(variant, "password") {
			return string(common.AttackWeakAuth)
		}
		if strings.Contains(variant, "session") {
			return string(common.AttackSessionFixation)
		}
		if strings.Contains(variant, "timeout") {
			return string(common.AttackSessionTimeout)
		}
		if strings.Contains(variant, "brute") {
			return string(common.AttackBruteForce)
		}
		if strings.Contains(variant, "deserialization") {
			return string(common.AttackInsecureDeserialization)
		}
		if strings.Contains(variant, "code") {
			return string(common.AttackCodeInjection)
		}
		if strings.Contains(variant, "supply") || strings.Contains(variant, "chain") {
			return string(common.AttackSupplyChainAttack)
		}
		if strings.Contains(variant, "log") {
			return string(common.AttackLogInjection)
		}
		if strings.Contains(variant, "bypass") {
			return string(common.AttackLogBypass)
		}
		if strings.Contains(variant, "audit") || strings.Contains(variant, "tamper") {
			return string(common.AttackAuditTrailTampering)
		}
		if strings.Contains(variant, "redirect") {
			return string(common.AttackOpenRedirect)
		}
	}

	// Check payload patterns
	payload := extractPayload(req)
	if payload != "" {
		// Map payload patterns to attack types
		return c.mapPayloadToAttackType(payload)
	}

	return ""
}

// mapPayloadToAttackType maps payload patterns to attack types
func (c *Checker) mapPayloadToAttackType(payload string) string {
	// XSS patterns
	if strings.Contains(payload, "<script>") || strings.Contains(payload, "javascript:") ||
		strings.Contains(payload, "onerror=") || strings.Contains(payload, "onload=") {
		return string(common.AttackXSS)
	}

	// SQL Injection patterns
	if strings.Contains(payload, "' OR '1'='1") || strings.Contains(payload, "UNION SELECT") ||
		strings.Contains(payload, "DROP TABLE") || strings.Contains(payload, "WAITFOR DELAY") {
		return string(common.AttackSQLi)
	}

	// Command Injection patterns
	if strings.Contains(payload, "cat /etc/passwd") || strings.Contains(payload, "whoami") ||
		strings.Contains(payload, "`id`") || strings.Contains(payload, "$(id)") {
		return string(common.AttackCommandInj)
	}

	// SSRF patterns
	if strings.Contains(payload, "127.0.0.1") || strings.Contains(payload, "localhost") ||
		strings.Contains(payload, "169.254.169.254") {
		return string(common.AttackSSRF)
	}

	// XXE patterns
	if strings.Contains(payload, "<!DOCTYPE") || strings.Contains(payload, "&xxe;") {
		return string(common.AttackXXE)
	}

	// LDAP Injection patterns
	if strings.Contains(payload, "*)(uid=*") || strings.Contains(payload, "admin)(&)") {
		return string(common.AttackLDAPInjection)
	}

	// NoSQL Injection patterns
	if strings.Contains(payload, "{\"$ne\":") || strings.Contains(payload, "{\"$gt\":") {
		return string(common.AttackNoSQLInjection)
	}

	// Header Injection patterns
	if strings.Contains(payload, "\\r\\n") || strings.Contains(payload, "%0d%0a") {
		return string(common.AttackHeaderInjection)
	}

	// Template Injection patterns
	if strings.Contains(payload, "{{7*7}}") || strings.Contains(payload, "${7*7}") {
		return string(common.AttackTemplateInjection)
	}

	// Broken Access Control patterns
	if strings.Contains(payload, "/admin") || strings.Contains(payload, "/api/admin") {
		return string(common.AttackBrokenAccessControl)
	}

	// IDOR patterns
	if strings.Contains(payload, "user_id") || strings.Contains(payload, "id=") {
		return string(common.AttackIDOR)
	}

	// Privilege Escalation patterns
	if strings.Contains(payload, "role=admin") || strings.Contains(payload, "isAdmin=true") {
		return string(common.AttackPrivilegeEscalation)
	}

	// JWT Manipulation patterns
	if strings.Contains(payload, "eyJhbGciOiJub25l") || strings.Contains(payload, "eyJhbGciOiJIUzI1NiI") {
		return string(common.AttackJWTManipulation)
	}

	// Weak Crypto patterns
	if strings.Contains(payload, "md5") || strings.Contains(payload, "sha1") {
		return string(common.AttackWeakCrypto)
	}

	// Weak Hashing patterns
	if strings.Contains(payload, "5f4dcc3b5aa765d61d8327deb882cf99") {
		return string(common.AttackWeakHashing)
	}

	// Insecure Transport patterns
	if strings.Contains(payload, "http://") || strings.Contains(payload, "ftp://") {
		return string(common.AttackInsecureTransport)
	}

	// Business Logic Flaw patterns
	if strings.Contains(payload, "quantity=-1") || strings.Contains(payload, "price=0") {
		return string(common.AttackBusinessLogicFlaw)
	}

	// Race Condition patterns
	if strings.Contains(payload, "concurrent=true") || strings.Contains(payload, "thread=1") {
		return string(common.AttackRaceCondition)
	}

	// Default Credentials patterns
	if strings.Contains(payload, "admin:admin") || strings.Contains(payload, "root:root") {
		return string(common.AttackDefaultCredentials)
	}

	// Debug Mode patterns
	if strings.Contains(payload, "debug=true") || strings.Contains(payload, "development=true") {
		return string(common.AttackDebugMode)
	}

	// Verbose Errors patterns
	if strings.Contains(payload, "error=verbose") || strings.Contains(payload, "debug=1") {
		return string(common.AttackVerboseErrors)
	}

	// Weak CORS patterns
	if strings.Contains(payload, "Origin: https://evil.com") || strings.Contains(payload, "Origin: *") {
		return string(common.AttackWeakCORS)
	}

	// Known Vulnerability patterns
	if strings.Contains(payload, "log4j") || strings.Contains(payload, "spring4shell") {
		return string(common.AttackKnownVulnerability)
	}

	// Outdated Component patterns
	if strings.Contains(payload, "jquery-1.12.4") || strings.Contains(payload, "bootstrap-3.4.1") {
		return string(common.AttackOutdatedComponent)
	}

	// Version Disclosure patterns
	if strings.Contains(payload, "version=1.0.0") || strings.Contains(payload, "build=2021") {
		return string(common.AttackVersionDisclosure)
	}

	// Weak Auth patterns
	if strings.Contains(payload, "password=123456") || strings.Contains(payload, "password=password") {
		return string(common.AttackWeakAuth)
	}

	// Session Fixation patterns
	if strings.Contains(payload, "sessionid=fixed") || strings.Contains(payload, "token=static") {
		return string(common.AttackSessionFixation)
	}

	// Session Timeout patterns
	if strings.Contains(payload, "timeout=0") || strings.Contains(payload, "expires=never") {
		return string(common.AttackSessionTimeout)
	}

	// Weak Password patterns
	if strings.Contains(payload, "password=123") || strings.Contains(payload, "password=abc") {
		return string(common.AttackWeakPassword)
	}

	// Brute Force patterns
	if strings.Contains(payload, "attempt=1000") || strings.Contains(payload, "delay=0") {
		return string(common.AttackBruteForce)
	}

	// Insecure Deserialization patterns
	if strings.Contains(payload, "O:8:\"stdClass\"") || strings.Contains(payload, "@type") {
		return string(common.AttackInsecureDeserialization)
	}

	// Code Injection patterns
	if strings.Contains(payload, "eval(") || strings.Contains(payload, "exec(") {
		return string(common.AttackCodeInjection)
	}

	// Supply Chain Attack patterns
	if strings.Contains(payload, "package=malicious") || strings.Contains(payload, "dependency=compromised") {
		return string(common.AttackSupplyChainAttack)
	}

	// Log Injection patterns
	if strings.Contains(payload, "admin\\nadmin") || strings.Contains(payload, "admin%0aadmin") {
		return string(common.AttackLogInjection)
	}

	// Log Bypass patterns
	if strings.Contains(payload, "logging=false") || strings.Contains(payload, "audit=off") {
		return string(common.AttackLogBypass)
	}

	// Audit Trail Tampering patterns
	if strings.Contains(payload, "timestamp=0") || strings.Contains(payload, "user=anonymous") {
		return string(common.AttackAuditTrailTampering)
	}

	// Open Redirect patterns
	if strings.Contains(payload, "https://evil.com") || strings.Contains(payload, "javascript:alert(1)") {
		return string(common.AttackOpenRedirect)
	}

	return ""
}

// checkXSS checks for XSS vulnerabilities with enhanced validation
func (c *Checker) checkXSS(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	payload := extractPayload(req)
	if payload == "" {
		return findings // No payload found
	}

	// Enhanced XSS detection with multiple validation layers
	for _, pattern := range c.patterns[common.AttackXSS] {
		if pattern.MatchString(resp.Body) {
			// Layer 1: Check if payload is reflected in response
			if !strings.Contains(resp.Body, payload) {
				continue // Payload not reflected, skip
			}

			// Layer 2: Check if payload is properly encoded (false positive reduction)
			if c.isPayloadEncoded(resp.Body, payload) {
				continue // Payload is encoded, likely not vulnerable
			}

			// Layer 3: Check response content type
			if c.isResponseSafe(resp) {
				continue // Response type suggests it's safe
			}

			// Layer 4: Check if payload is in a safe context
			if c.isPayloadInSafeContext(resp.Body, payload) {
				continue // Payload in safe context
			}

			// Layer 5: Verify payload reflection pattern
			reflectionPattern := c.analyzeReflectionPattern(resp.Body, payload)
			if reflectionPattern == "safe" {
				continue // Safe reflection pattern
			}

			// All checks passed - likely vulnerable
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackXSS),
				Category:       common.OWASPCategoryA03Injection,
				Severity:       c.determineXSSSeverity(reflectionPattern),
				Title:          fmt.Sprintf("Cross-Site Scripting (XSS) - %s", reflectionPattern),
				Description:    fmt.Sprintf("XSS payload was reflected in the response. Reflection pattern: %s", reflectionPattern),
				Evidence:       extractEvidence(resp.Body, payload),
				Payload:        payload,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// isPayloadEncoded checks if the payload is properly encoded in response
func (c *Checker) isPayloadEncoded(responseBody, payload string) bool {
	// Check for HTML encoding
	encodedPayload := strings.ReplaceAll(payload, "<", "&lt;")
	encodedPayload = strings.ReplaceAll(encodedPayload, ">", "&gt;")
	encodedPayload = strings.ReplaceAll(encodedPayload, "\"", "&quot;")
	encodedPayload = strings.ReplaceAll(encodedPayload, "'", "&#39;")

	return strings.Contains(responseBody, encodedPayload)
}

// isResponseSafe checks if response content type suggests it's safe
func (c *Checker) isResponseSafe(resp *common.RecordedResponse) bool {
	contentType := strings.ToLower(resp.ContentType)

	// Safe content types
	safeTypes := []string{
		"application/json",
		"application/xml",
		"text/plain",
		"image/",
		"audio/",
		"video/",
	}

	for _, safeType := range safeTypes {
		if strings.Contains(contentType, safeType) {
			return true
		}
	}

	return false
}

// isPayloadInSafeContext checks if payload is in a safe context
func (c *Checker) isPayloadInSafeContext(responseBody, payload string) bool {
	// Check if payload is in HTML comments
	if strings.Contains(responseBody, "<!--"+payload+"-->") {
		return true
	}

	// Check if payload is in script tags (might be safe if properly handled)
	if strings.Contains(responseBody, "<script>") && strings.Contains(responseBody, payload) {
		// Additional check needed for script context
		return false // For now, consider script context as potentially vulnerable
	}

	// Check if payload is in attribute values (might be safe if quoted)
	if strings.Contains(responseBody, "=\""+payload+"\"") || strings.Contains(responseBody, "='"+payload+"'") {
		return false // Attribute context can be vulnerable
	}

	return false
}

// analyzeReflectionPattern analyzes how the payload is reflected
func (c *Checker) analyzeReflectionPattern(responseBody, payload string) string {
	// Check for direct reflection
	if strings.Contains(responseBody, payload) {
		// Check if it's in a dangerous context
		if strings.Contains(responseBody, "<script>"+payload) {
			return "script_context"
		}
		if strings.Contains(responseBody, "onload="+payload) || strings.Contains(responseBody, "onerror="+payload) {
			return "event_handler"
		}
		if strings.Contains(responseBody, "javascript:"+payload) {
			return "javascript_protocol"
		}
		return "direct_reflection"
	}

	return "safe"
}

// determineXSSSeverity determines severity based on reflection pattern
func (c *Checker) determineXSSSeverity(reflectionPattern string) common.Severity {
	switch reflectionPattern {
	case "script_context", "event_handler", "javascript_protocol":
		return common.SeverityCritical
	case "direct_reflection":
		return common.SeverityHigh
	default:
		return common.SeverityMedium
	}
}

// checkSQLi checks for SQL injection vulnerabilities with enhanced validation
func (c *Checker) checkSQLi(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	payload := extractPayload(req)
	if payload == "" {
		return findings // No payload found
	}

	// Enhanced SQL injection detection
	for _, pattern := range c.patterns[common.AttackSQLi] {
		if pattern.MatchString(resp.Body) {
			// Layer 1: Check if payload is reflected in response
			if !strings.Contains(resp.Body, payload) {
				continue // Payload not reflected, skip
			}

			// Layer 2: Check if it's a false positive (common error messages)
			if c.isSQLiFalsePositive(resp.Body, payload) {
				continue // Likely false positive
			}

			// Layer 3: Check response status code
			if resp.StatusCode >= 500 {
				// Server error - more likely to be real SQL injection
				finding := common.Finding{
					ID:             generateID(),
					RequestID:      req.ID,
					ResponseID:     resp.ID,
					Type:           string(common.AttackSQLi),
					Category:       common.OWASPCategoryA03Injection,
					Severity:       common.SeverityCritical,
					Title:          "SQL Injection - Error Based (Server Error)",
					Description:    "SQL injection error detected with server error response",
					Evidence:       extractEvidence(resp.Body, pattern.String()),
					Payload:        payload,
					URL:            req.URL,
					Method:         req.Method,
					ResponseStatus: resp.StatusCode,
					ResponseSize:   resp.Size,
					ResponseTime:   resp.Duration,
					Blocked:        false,
					RateLimited:    false,
					Forbidden:      false,
					ServerError:    false,
					Timestamp:      time.Now(),
				}
				findings = append(findings, finding)
			} else if resp.StatusCode == 200 {
				// 200 response with SQL error - still concerning
				finding := common.Finding{
					ID:             generateID(),
					RequestID:      req.ID,
					ResponseID:     resp.ID,
					Type:           string(common.AttackSQLi),
					Category:       common.OWASPCategoryA03Injection,
					Severity:       common.SeverityHigh,
					Title:          "SQL Injection - Error Based (200 Response)",
					Description:    "SQL injection error detected in successful response",
					Evidence:       extractEvidence(resp.Body, pattern.String()),
					Payload:        payload,
					URL:            req.URL,
					Method:         req.Method,
					ResponseStatus: resp.StatusCode,
					ResponseSize:   resp.Size,
					ResponseTime:   resp.Duration,
					Blocked:        false,
					RateLimited:    false,
					Forbidden:      false,
					ServerError:    false,
					Timestamp:      time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// isSQLiFalsePositive checks if SQL injection detection is likely a false positive
func (c *Checker) isSQLiFalsePositive(responseBody, payload string) bool {
	// Common false positive patterns
	falsePositivePatterns := []string{
		"sql syntax",
		"mysql error",
		"database error",
		"connection error",
		"server error",
		"internal error",
	}

	// If response contains generic error messages without specific SQL syntax
	hasGenericError := false
	for _, pattern := range falsePositivePatterns {
		if strings.Contains(strings.ToLower(responseBody), pattern) {
			hasGenericError = true
			break
		}
	}

	// If it's a generic error and payload is not SQL-specific, likely false positive
	if hasGenericError && !c.isSQLSpecificPayload(payload) {
		return true
	}

	return false
}

// isSQLSpecificPayload checks if payload contains SQL-specific syntax
func (c *Checker) isSQLSpecificPayload(payload string) bool {
	sqlPatterns := []string{
		"' OR '1'='1",
		"' UNION SELECT",
		"'; DROP TABLE",
		"' AND 1=1",
		"' OR 1=1",
		"UNION SELECT",
		"DROP TABLE",
		"INSERT INTO",
		"UPDATE SET",
		"DELETE FROM",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(strings.ToUpper(payload), pattern) {
			return true
		}
	}

	return false
}

// checkXXE checks for XXE vulnerabilities
func (c *Checker) checkXXE(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	for _, pattern := range c.patterns[common.AttackXXE] {
		if pattern.MatchString(resp.Body) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackXXE),
				Category:       common.OWASPCategoryA05SecurityMisconfiguration,
				Severity:       common.SeverityCritical,
				Title:          "XML External Entity (XXE) Injection",
				Description:    "XXE vulnerability detected in response",
				Evidence:       extractEvidence(resp.Body, pattern.String()),
				Payload:        extractPayload(req),
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkSSRF checks for SSRF vulnerabilities
func (c *Checker) checkSSRF(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for SSRF patterns
	ssrfPatterns := []string{
		"127.0.0.1",
		"localhost",
		"169.254.169.254",
		"metadata.google.internal",
		"169.254.170.2",
	}

	for _, pattern := range ssrfPatterns {
		if strings.Contains(resp.Body, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackSSRF),
				Category:       common.OWASPCategoryA10SSRF,
				Severity:       common.SeverityHigh,
				Title:          "Server-Side Request Forgery (SSRF)",
				Description:    "SSRF vulnerability detected in response",
				Evidence:       extractEvidence(resp.Body, pattern),
				Payload:        extractPayload(req),
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for XXE patterns
	xxePatterns := []string{
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM",
		"xmlns:xi=\"http://www.w3.org/2001/XInclude\"",
	}

	for _, pattern := range xxePatterns {
		if strings.Contains(req.Body, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackXXE),
				Category:       common.OWASPCategoryA10SSRF,
				Severity:       common.SeverityCritical,
				Title:          "XML External Entity (XXE) Injection",
				Description:    "XXE vulnerability detected",
				Evidence:       fmt.Sprintf("XXE pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for open redirect patterns
	openRedirectPatterns := []string{
		"https://evil.com",
		"//evil.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	}

	for _, pattern := range openRedirectPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackOpenRedirect),
				Category:       common.OWASPCategoryA10SSRF,
				Severity:       common.SeverityMedium,
				Title:          "Open Redirect",
				Description:    "Open redirect vulnerability detected",
				Evidence:       fmt.Sprintf("Open redirect pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
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
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
	}

	for header, expectedValue := range securityHeaders {
		if value, exists := resp.Headers[header]; !exists {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           "missing_security_header",
				Category:       common.OWASPCategoryA05SecurityMisconfiguration,
				Severity:       common.SeverityMedium,
				Title:          fmt.Sprintf("Missing Security Header: %s", header),
				Description:    fmt.Sprintf("Security header %s is missing from response", header),
				Evidence:       fmt.Sprintf("Header %s not found in response headers", header),
				Payload:        "",
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		} else if value != expectedValue {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           "weak_security_header",
				Category:       common.OWASPCategoryA05SecurityMisconfiguration,
				Severity:       common.SeverityLow,
				Title:          fmt.Sprintf("Weak Security Header: %s", header),
				Description:    fmt.Sprintf("Security header %s has weak value: %s", header, value),
				Evidence:       fmt.Sprintf("Header %s = %s (expected: %s)", header, value, expectedValue),
				Payload:        "",
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkResponseBlocking checks for various response blocking and security measures
func (c *Checker) checkResponseBlocking(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Enhanced WAF/IPS blocking patterns
	blockingPatterns := []string{
		"access denied",
		"forbidden",
		"blocked",
		"security violation",
		"malicious request",
		"attack detected",
		"request blocked",
		"unauthorized",
		"cloudflare",
		"cloudfront",
		"akamai",
		"fastly",
		"incapsula",
		"imperva",
		"f5",
		"barracuda",
		"fortinet",
		"mod_security",
		"waf",
		"firewall",
		"security gateway",
		"threat detected",
		"suspicious activity",
	}

	// Rate limiting patterns
	rateLimitPatterns := []string{
		"rate limit exceeded",
		"too many requests",
		"quota exceeded",
		"throttled",
		"rate limiting",
		"request limit",
		"429",
		"retry after",
	}

	// Check response status codes
	isBlocked := false
	isRateLimited := false
	isForbidden := false
	isServerError := false

	// Enhanced status code analysis
	switch {
	case resp.StatusCode == 403:
		isForbidden = true
		isBlocked = true // 403 often indicates WAF blocking
	case resp.StatusCode == 401:
		isForbidden = true
	case resp.StatusCode == 429:
		isRateLimited = true
	case resp.StatusCode == 406:
		isBlocked = true // Not Acceptable - often WAF
	case resp.StatusCode == 444:
		isBlocked = true // Nginx specific - connection closed
	case resp.StatusCode >= 500:
		isServerError = true
	}

	// Check response body for blocking patterns
	responseBodyLower := strings.ToLower(resp.Body)

	// Check for blocking patterns
	for _, pattern := range blockingPatterns {
		if strings.Contains(responseBodyLower, pattern) {
			isBlocked = true
			break
		}
	}

	// Check for rate limiting patterns
	for _, pattern := range rateLimitPatterns {
		if strings.Contains(responseBodyLower, pattern) {
			isRateLimited = true
			break
		}
	}

	// Enhanced response headers analysis
	securityHeaders := map[string]bool{
		"x-waf":        true,
		"x-security":   true,
		"x-blocked":    true,
		"cf-ray":       true, // Cloudflare
		"x-cdn":        true,
		"x-rate-limit": true,
		"retry-after":  true,
		"x-powered-by": false, // Check if WAF info is exposed
		"server":       false, // Check server info
	}

	for header, value := range resp.Headers {
		headerLower := strings.ToLower(header)

		// Check for security headers
		if securityHeaders[headerLower] {
			isBlocked = true
		}

		// Check header values for blocking indicators
		valueLower := strings.ToLower(value)
		if strings.Contains(valueLower, "cloudflare") ||
			strings.Contains(valueLower, "akamai") ||
			strings.Contains(valueLower, "fastly") ||
			strings.Contains(valueLower, "imperva") {
			isBlocked = true
		}
	}

	// Check for empty or very small responses (often indicates blocking)
	if resp.Size < 100 && resp.StatusCode != 204 {
		isBlocked = true
	}

	// Create findings for different blocking scenarios
	if isBlocked {
		finding := common.Finding{
			ID:             generateID(),
			RequestID:      req.ID,
			ResponseID:     resp.ID,
			Type:           "waf_blocked",
			Category:       common.OWASPCategoryA05SecurityMisconfiguration,
			Severity:       common.SeverityMedium,
			Title:          "WAF/IPS Blocking Detected",
			Description:    "Request was blocked by WAF/IPS security measures",
			Evidence:       fmt.Sprintf("Response contains blocking patterns. Status: %d, Size: %d", resp.StatusCode, resp.Size),
			Payload:        extractPayload(req),
			URL:            req.URL,
			Method:         req.Method,
			ResponseStatus: resp.StatusCode,
			ResponseSize:   resp.Size,
			ResponseTime:   resp.Duration,
			Blocked:        true,
			RateLimited:    false,
			Forbidden:      false,
			ServerError:    false,
			Timestamp:      time.Now(),
		}
		findings = append(findings, finding)
	}

	if isRateLimited {
		finding := common.Finding{
			ID:             generateID(),
			RequestID:      req.ID,
			ResponseID:     resp.ID,
			Type:           "rate_limited",
			Category:       common.OWASPCategoryA05SecurityMisconfiguration,
			Severity:       common.SeverityLow,
			Title:          "Rate Limiting Detected",
			Description:    "Request was rate limited by the server",
			Evidence:       fmt.Sprintf("Rate limiting detected. Status: %d", resp.StatusCode),
			Payload:        extractPayload(req),
			URL:            req.URL,
			Method:         req.Method,
			ResponseStatus: resp.StatusCode,
			ResponseSize:   resp.Size,
			ResponseTime:   resp.Duration,
			Blocked:        false,
			RateLimited:    true,
			Forbidden:      false,
			ServerError:    false,
			Timestamp:      time.Now(),
		}
		findings = append(findings, finding)
	}

	if isForbidden {
		finding := common.Finding{
			ID:             generateID(),
			RequestID:      req.ID,
			ResponseID:     resp.ID,
			Type:           "access_denied",
			Category:       common.OWASPCategoryA01BrokenAccessControl,
			Severity:       common.SeverityMedium,
			Title:          "Access Denied",
			Description:    "Request was denied due to access control",
			Evidence:       fmt.Sprintf("Access denied. Status: %d", resp.StatusCode),
			Payload:        extractPayload(req),
			URL:            req.URL,
			Method:         req.Method,
			ResponseStatus: resp.StatusCode,
			ResponseSize:   resp.Size,
			ResponseTime:   resp.Duration,
			Blocked:        false,
			RateLimited:    false,
			Forbidden:      true,
			ServerError:    false,
			Timestamp:      time.Now(),
		}
		findings = append(findings, finding)
	}

	if isServerError {
		finding := common.Finding{
			ID:             generateID(),
			RequestID:      req.ID,
			ResponseID:     resp.ID,
			Type:           "server_error",
			Category:       common.OWASPCategoryA05SecurityMisconfiguration,
			Severity:       common.SeverityLow,
			Title:          "Server Error",
			Description:    "Server error occurred during request processing",
			Evidence:       fmt.Sprintf("Server error. Status: %d", resp.StatusCode),
			Payload:        extractPayload(req),
			URL:            req.URL,
			Method:         req.Method,
			ResponseStatus: resp.StatusCode,
			ResponseSize:   resp.Size,
			ResponseTime:   resp.Duration,
			Blocked:        false,
			RateLimited:    false,
			Forbidden:      false,
			ServerError:    true,
			Timestamp:      time.Now(),
		}
		findings = append(findings, finding)
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
	return uuid.New().String()
}

// A01:2021 - Broken Access Control
func (c *Checker) checkBrokenAccessControl(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for successful access to admin endpoints
	adminPatterns := []string{
		"/admin",
		"/api/admin",
		"/dashboard",
		"/user/admin",
		"/config",
		"/management",
		"/console",
	}

	for _, pattern := range adminPatterns {
		if strings.Contains(req.URL, pattern) && resp.StatusCode == 200 {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackBrokenAccessControl),
				Category:       common.OWASPCategoryA01BrokenAccessControl,
				Severity:       common.SeverityHigh,
				Title:          "Broken Access Control - Admin Access",
				Description:    "Unauthorized access to admin endpoint detected",
				Evidence:       fmt.Sprintf("Successfully accessed %s with status %d", pattern, resp.StatusCode),
				Payload:        req.URL,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for IDOR vulnerabilities
	idorPatterns := []string{
		"user_id",
		"id=",
		"user=",
		"account=",
	}

	for _, pattern := range idorPatterns {
		if strings.Contains(req.URL, pattern) && resp.StatusCode == 200 {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackIDOR),
				Category:       common.OWASPCategoryA01BrokenAccessControl,
				Severity:       common.SeverityHigh,
				Title:          "Insecure Direct Object Reference (IDOR)",
				Description:    "Potential IDOR vulnerability detected",
				Evidence:       fmt.Sprintf("Accessed resource with %s pattern, status %d", pattern, resp.StatusCode),
				Payload:        req.URL,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for privilege escalation
	privilegePatterns := []string{
		"role=admin",
		"role=superuser",
		"isAdmin=true",
		"privilege=all",
	}

	for _, pattern := range privilegePatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackPrivilegeEscalation),
				Category:       common.OWASPCategoryA01BrokenAccessControl,
				Severity:       common.SeverityHigh,
				Title:          "Privilege Escalation Attempt",
				Description:    "Privilege escalation attempt detected",
				Evidence:       fmt.Sprintf("Privilege escalation pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for JWT manipulation
	jwtPatterns := []string{
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}

	for _, pattern := range jwtPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackJWTManipulation),
				Category:       common.OWASPCategoryA01BrokenAccessControl,
				Severity:       common.SeverityHigh,
				Title:          "JWT Manipulation Attempt",
				Description:    "JWT manipulation attempt detected",
				Evidence:       fmt.Sprintf("JWT manipulation pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// A02:2021 - Cryptographic Failures
func (c *Checker) checkCryptographicFailures(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for weak crypto algorithms in response
	weakCryptoPatterns := []string{
		"md5",
		"sha1",
		"des",
		"rc4",
		"md4",
	}

	for _, pattern := range weakCryptoPatterns {
		if strings.Contains(strings.ToLower(resp.Body), pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackWeakCrypto),
				Category:       common.OWASPCategoryA02CryptographicFailures,
				Severity:       common.SeverityMedium,
				Title:          "Weak Cryptographic Algorithm",
				Description:    "Weak cryptographic algorithm detected in response",
				Evidence:       fmt.Sprintf("Found weak crypto pattern: %s", pattern),
				Payload:        extractPayload(req),
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for weak hashing
	weakHashPatterns := []string{
		"5f4dcc3b5aa765d61d8327deb882cf99",         // md5 hash
		"40bd001563085fc35165329ea1ff5c5ecbdbbeef", // sha1 hash
	}

	for _, pattern := range weakHashPatterns {
		if strings.Contains(resp.Body, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackWeakHashing),
				Category:       common.OWASPCategoryA02CryptographicFailures,
				Severity:       common.SeverityMedium,
				Title:          "Weak Hashing Algorithm",
				Description:    "Weak hashing algorithm detected in response",
				Evidence:       fmt.Sprintf("Found weak hash pattern: %s", pattern),
				Payload:        extractPayload(req),
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for insecure transport
	insecureTransportPatterns := []string{
		"http://",
		"ftp://",
		"telnet://",
	}

	for _, pattern := range insecureTransportPatterns {
		if strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackInsecureTransport),
				Category:       common.OWASPCategoryA02CryptographicFailures,
				Severity:       common.SeverityHigh,
				Title:          "Insecure Transport Protocol",
				Description:    "Insecure transport protocol detected",
				Evidence:       fmt.Sprintf("Insecure transport pattern: %s", pattern),
				Payload:        req.URL,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// A03:2021 - Injection
func (c *Checker) checkInjection(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for XSS
	xssFindings := c.checkXSS(req, resp)
	findings = append(findings, xssFindings...)

	// Check for SQL Injection
	sqliFindings := c.checkSQLi(req, resp)
	findings = append(findings, sqliFindings...)

	// Check for Command Injection
	cmdFindings := c.checkCommandInjection(req, resp)
	findings = append(findings, cmdFindings...)

	// Check for LDAP Injection
	ldapFindings := c.checkLDAPInjection(req, resp)
	findings = append(findings, ldapFindings...)

	// Check for NoSQL Injection
	nosqlFindings := c.checkNoSQLInjection(req, resp)
	findings = append(findings, nosqlFindings...)

	// Check for Header Injection
	headerFindings := c.checkHeaderInjection(req, resp)
	findings = append(findings, headerFindings...)

	// Check for Template Injection
	templateFindings := c.checkTemplateInjection(req, resp)
	findings = append(findings, templateFindings...)

	return findings
}

// A04:2021 - Insecure Design
func (c *Checker) checkInsecureDesign(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for business logic flaws
	businessLogicPatterns := []string{
		"quantity=-1",
		"price=0",
		"amount=999999999",
	}

	for _, pattern := range businessLogicPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackBusinessLogicFlaw),
				Category:       common.OWASPCategoryA04InsecureDesign,
				Severity:       common.SeverityMedium,
				Title:          "Business Logic Flaw",
				Description:    "Potential business logic vulnerability detected",
				Evidence:       fmt.Sprintf("Business logic flaw pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for race conditions
	raceConditionPatterns := []string{
		"concurrent=true",
		"thread=1",
	}

	for _, pattern := range raceConditionPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackRaceCondition),
				Category:       common.OWASPCategoryA04InsecureDesign,
				Severity:       common.SeverityMedium,
				Title:          "Race Condition",
				Description:    "Potential race condition vulnerability detected",
				Evidence:       fmt.Sprintf("Race condition pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// A05:2021 - Security Misconfiguration
func (c *Checker) checkSecurityMisconfiguration(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for missing security headers
	requiredHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	}

	missingHeaders := []string{}
	for _, header := range requiredHeaders {
		if _, exists := resp.Headers[header]; !exists {
			missingHeaders = append(missingHeaders, header)
		}
	}

	if len(missingHeaders) > 0 {
		finding := common.Finding{
			ID:             generateID(),
			RequestID:      req.ID,
			ResponseID:     resp.ID,
			Type:           string(common.AttackMissingHeaders),
			Category:       common.OWASPCategoryA05SecurityMisconfiguration,
			Severity:       common.SeverityMedium,
			Title:          "Missing Security Headers",
			Description:    "Important security headers are missing",
			Evidence:       fmt.Sprintf("Missing headers: %s", strings.Join(missingHeaders, ", ")),
			Payload:        extractPayload(req),
			URL:            req.URL,
			Method:         req.Method,
			ResponseStatus: resp.StatusCode,
			ResponseSize:   resp.Size,
			ResponseTime:   resp.Duration,
			Blocked:        false,
			RateLimited:    false,
			Forbidden:      false,
			ServerError:    false,
			Timestamp:      time.Now(),
		}
		findings = append(findings, finding)
	}

	// Check for default credentials
	defaultCredPatterns := []string{
		"admin:admin",
		"root:root",
		"admin:password",
		"guest:guest",
	}

	for _, pattern := range defaultCredPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackDefaultCredentials),
				Category:       common.OWASPCategoryA05SecurityMisconfiguration,
				Severity:       common.SeverityHigh,
				Title:          "Default Credentials",
				Description:    "Default credentials detected",
				Evidence:       fmt.Sprintf("Default credentials pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for debug mode
	debugPatterns := []string{
		"debug=true",
		"development=true",
		"test=true",
	}

	for _, pattern := range debugPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackDebugMode),
				Category:       common.OWASPCategoryA05SecurityMisconfiguration,
				Severity:       common.SeverityMedium,
				Title:          "Debug Mode Enabled",
				Description:    "Debug mode is enabled",
				Evidence:       fmt.Sprintf("Debug mode pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for verbose errors
	verboseErrorPatterns := []string{
		"error=verbose",
		"debug=1",
	}

	for _, pattern := range verboseErrorPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackVerboseErrors),
				Category:       common.OWASPCategoryA05SecurityMisconfiguration,
				Severity:       common.SeverityMedium,
				Title:          "Verbose Error Messages",
				Description:    "Verbose error messages are enabled",
				Evidence:       fmt.Sprintf("Verbose error pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for weak CORS
	weakCORSPatterns := []string{
		"Origin: https://evil.com",
		"Origin: null",
		"Origin: *",
	}

	for _, pattern := range weakCORSPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackWeakCORS),
				Category:       common.OWASPCategoryA05SecurityMisconfiguration,
				Severity:       common.SeverityMedium,
				Title:          "Weak CORS Configuration",
				Description:    "Weak CORS configuration detected",
				Evidence:       fmt.Sprintf("Weak CORS pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// A06:2021 - Vulnerable and Outdated Components
func (c *Checker) checkVulnerableComponents(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for known vulnerable components
	vulnerableComponents := []string{
		"log4j",
		"spring4shell",
		"heartbleed",
		"shellshock",
		"struts",
	}

	for _, component := range vulnerableComponents {
		if strings.Contains(strings.ToLower(resp.Body), component) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackKnownVulnerability),
				Category:       common.OWASPCategoryA06VulnerableComponents,
				Severity:       common.SeverityHigh,
				Title:          "Known Vulnerable Component",
				Description:    "Known vulnerable component detected",
				Evidence:       fmt.Sprintf("Vulnerable component found: %s", component),
				Payload:        extractPayload(req),
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for outdated components
	outdatedComponents := []string{
		"jquery-1.12.4",
		"bootstrap-3.4.1",
		"angular-1.7.9",
	}

	for _, component := range outdatedComponents {
		if strings.Contains(strings.ToLower(resp.Body), component) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackOutdatedComponent),
				Category:       common.OWASPCategoryA06VulnerableComponents,
				Severity:       common.SeverityMedium,
				Title:          "Outdated Component",
				Description:    "Outdated component detected",
				Evidence:       fmt.Sprintf("Outdated component found: %s", component),
				Payload:        extractPayload(req),
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for version disclosure
	versionPatterns := []string{
		"version=1.0.0",
		"build=2021",
	}

	for _, pattern := range versionPatterns {
		if strings.Contains(strings.ToLower(resp.Body), pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackVersionDisclosure),
				Category:       common.OWASPCategoryA06VulnerableComponents,
				Severity:       common.SeverityLow,
				Title:          "Version Information Disclosure",
				Description:    "Version information exposed in response",
				Evidence:       fmt.Sprintf("Version pattern found: %s", pattern),
				Payload:        extractPayload(req),
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// A07:2021 - Identification and Authentication Failures
func (c *Checker) checkAuthFailures(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for weak authentication
	weakAuthPatterns := []string{
		"password=123456",
		"password=password",
		"password=admin",
	}

	for _, pattern := range weakAuthPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackWeakAuth),
				Category:       common.OWASPCategoryA07AuthFailures,
				Severity:       common.SeverityHigh,
				Title:          "Weak Authentication",
				Description:    "Weak authentication credentials detected",
				Evidence:       fmt.Sprintf("Weak auth pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for session fixation
	sessionFixationPatterns := []string{
		"sessionid=fixed",
		"token=static",
	}

	for _, pattern := range sessionFixationPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackSessionFixation),
				Category:       common.OWASPCategoryA07AuthFailures,
				Severity:       common.SeverityMedium,
				Title:          "Session Fixation",
				Description:    "Session fixation vulnerability detected",
				Evidence:       fmt.Sprintf("Session fixation pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for session timeout
	sessionTimeoutPatterns := []string{
		"timeout=0",
		"expires=never",
	}

	for _, pattern := range sessionTimeoutPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackSessionTimeout),
				Category:       common.OWASPCategoryA07AuthFailures,
				Severity:       common.SeverityMedium,
				Title:          "Session Timeout",
				Description:    "Session timeout vulnerability detected",
				Evidence:       fmt.Sprintf("Session timeout pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for weak passwords
	weakPasswordPatterns := []string{
		"password=123",
		"password=abc",
		"password=123456789",
	}

	for _, pattern := range weakPasswordPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackWeakPassword),
				Category:       common.OWASPCategoryA07AuthFailures,
				Severity:       common.SeverityHigh,
				Title:          "Weak Password",
				Description:    "Weak password detected",
				Evidence:       fmt.Sprintf("Weak password pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for brute force
	bruteForcePatterns := []string{
		"attempt=1000",
		"delay=0",
	}

	for _, pattern := range bruteForcePatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackBruteForce),
				Category:       common.OWASPCategoryA07AuthFailures,
				Severity:       common.SeverityMedium,
				Title:          "Brute Force Attempt",
				Description:    "Brute force attempt detected",
				Evidence:       fmt.Sprintf("Brute force pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// A08:2021 - Software and Data Integrity Failures
func (c *Checker) checkDataIntegrityFailures(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for insecure deserialization
	deserializationPatterns := []string{
		"O:8:\"stdClass\"",
		"@type",
		"java.util.ArrayList",
		"rce",
	}

	for _, pattern := range deserializationPatterns {
		if strings.Contains(req.Body, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackInsecureDeserialization),
				Category:       common.OWASPCategoryA08SoftwareDataIntegrity,
				Severity:       common.SeverityHigh,
				Title:          "Insecure Deserialization",
				Description:    "Insecure deserialization pattern detected",
				Evidence:       fmt.Sprintf("Deserialization pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for code injection
	codeInjectionPatterns := []string{
		"eval('alert(1)')",
		"exec('whoami')",
		"system('id')",
	}

	for _, pattern := range codeInjectionPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackCodeInjection),
				Category:       common.OWASPCategoryA08SoftwareDataIntegrity,
				Severity:       common.SeverityCritical,
				Title:          "Code Injection",
				Description:    "Code injection pattern detected",
				Evidence:       fmt.Sprintf("Code injection pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for supply chain attacks
	supplyChainPatterns := []string{
		"package=malicious",
		"dependency=compromised",
	}

	for _, pattern := range supplyChainPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackSupplyChainAttack),
				Category:       common.OWASPCategoryA08SoftwareDataIntegrity,
				Severity:       common.SeverityHigh,
				Title:          "Supply Chain Attack",
				Description:    "Supply chain attack pattern detected",
				Evidence:       fmt.Sprintf("Supply chain attack pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// A09:2021 - Security Logging and Monitoring Failures
func (c *Checker) checkLoggingFailures(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for log injection
	logInjectionPatterns := []string{
		"admin\nadmin",
		"admin\r\nadmin",
		"admin%0aadmin",
	}

	for _, pattern := range logInjectionPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackLogInjection),
				Category:       common.OWASPCategoryA09LoggingFailures,
				Severity:       common.SeverityMedium,
				Title:          "Log Injection",
				Description:    "Log injection pattern detected",
				Evidence:       fmt.Sprintf("Log injection pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for log bypass
	logBypassPatterns := []string{
		"logging=false",
		"audit=off",
	}

	for _, pattern := range logBypassPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackLogBypass),
				Category:       common.OWASPCategoryA09LoggingFailures,
				Severity:       common.SeverityMedium,
				Title:          "Log Bypass",
				Description:    "Log bypass attempt detected",
				Evidence:       fmt.Sprintf("Log bypass pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	// Check for audit trail tampering
	auditTamperingPatterns := []string{
		"timestamp=0",
		"user=anonymous",
	}

	for _, pattern := range auditTamperingPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           string(common.AttackAuditTrailTampering),
				Category:       common.OWASPCategoryA09LoggingFailures,
				Severity:       common.SeverityMedium,
				Title:          "Audit Trail Tampering",
				Description:    "Audit trail tampering attempt detected",
				Evidence:       fmt.Sprintf("Audit tampering pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// Additional injection check methods
func (c *Checker) checkCommandInjection(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Check for command injection patterns
	cmdPatterns := []string{
		"; cat /etc/passwd",
		"| whoami",
		"`id`",
		"$(id)",
		"& dir",
		"|| ping",
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           "command_injection",
				Category:       common.OWASPCategoryA03Injection,
				Severity:       common.SeverityCritical,
				Title:          "Command Injection",
				Description:    "Command injection pattern detected",
				Evidence:       fmt.Sprintf("Command injection pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (c *Checker) checkLDAPInjection(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	ldapPatterns := []string{
		"*)(uid=*))(|(uid=*",
		"admin)(&)",
		"*",
	}

	for _, pattern := range ldapPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           "ldap_injection",
				Category:       common.OWASPCategoryA03Injection,
				Severity:       common.SeverityHigh,
				Title:          "LDAP Injection",
				Description:    "LDAP injection pattern detected",
				Evidence:       fmt.Sprintf("LDAP injection pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (c *Checker) checkNoSQLInjection(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	nosqlPatterns := []string{
		"{\"$ne\": null}",
		"{\"$gt\": \"\"}",
		"{\"$where\": \"1==1\"}",
	}

	for _, pattern := range nosqlPatterns {
		if strings.Contains(req.Body, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           "nosql_injection",
				Category:       common.OWASPCategoryA03Injection,
				Severity:       common.SeverityHigh,
				Title:          "NoSQL Injection",
				Description:    "NoSQL injection pattern detected",
				Evidence:       fmt.Sprintf("NoSQL injection pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (c *Checker) checkHeaderInjection(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	headerPatterns := []string{
		"admin\r\nX-Forwarded-For: 127.0.0.1",
		"admin%0d%0aX-Forwarded-For: 127.0.0.1",
	}

	for _, pattern := range headerPatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           "header_injection",
				Category:       common.OWASPCategoryA03Injection,
				Severity:       common.SeverityHigh,
				Title:          "Header Injection",
				Description:    "Header injection pattern detected",
				Evidence:       fmt.Sprintf("Header injection pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

func (c *Checker) checkTemplateInjection(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	templatePatterns := []string{
		"{{7*7}}",
		"${7*7}",
		"#{7*7}",
	}

	for _, pattern := range templatePatterns {
		if strings.Contains(req.Body, pattern) || strings.Contains(req.URL, pattern) {
			finding := common.Finding{
				ID:             generateID(),
				RequestID:      req.ID,
				ResponseID:     resp.ID,
				Type:           "template_injection",
				Category:       common.OWASPCategoryA03Injection,
				Severity:       common.SeverityHigh,
				Title:          "Template Injection",
				Description:    "Template injection pattern detected",
				Evidence:       fmt.Sprintf("Template injection pattern: %s", pattern),
				Payload:        pattern,
				URL:            req.URL,
				Method:         req.Method,
				ResponseStatus: resp.StatusCode,
				ResponseSize:   resp.Size,
				ResponseTime:   resp.Duration,
				Blocked:        false,
				RateLimited:    false,
				Forbidden:      false,
				ServerError:    false,
				Timestamp:      time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// ResponseBehavior represents the analyzed response behavior
type ResponseBehavior struct {
	Description  string
	Evidence     string
	Blocked      bool
	RateLimited  bool
	Forbidden    bool
	ServerError  bool
	WAFDetected  bool
	IPSDetected  bool
	ErrorPattern string
	ResponseType string
	AnomalyScore int
}

// analyzeResponseBehavior analyzes the overall response behavior
func (c *Checker) analyzeResponseBehavior(req *common.RecordedRequest, resp *common.RecordedResponse) ResponseBehavior {
	behavior := ResponseBehavior{
		Description:  "Normal response",
		Evidence:     "No anomalies detected",
		Blocked:      false,
		RateLimited:  false,
		Forbidden:    false,
		ServerError:  false,
		WAFDetected:  false,
		IPSDetected:  false,
		ResponseType: "normal",
		AnomalyScore: 0,
	}

	// Check status codes
	switch resp.StatusCode {
	case 403:
		behavior.Forbidden = true
		behavior.Blocked = true
		behavior.Description = "Access forbidden - likely WAF blocking"
		behavior.Evidence = fmt.Sprintf("Status 403 - Access forbidden")
		behavior.ResponseType = "blocked"
		behavior.AnomalyScore += 80
	case 401:
		behavior.Forbidden = true
		behavior.Description = "Unauthorized access"
		behavior.Evidence = fmt.Sprintf("Status 401 - Unauthorized")
		behavior.ResponseType = "unauthorized"
		behavior.AnomalyScore += 60
	case 429:
		behavior.RateLimited = true
		behavior.Description = "Rate limited"
		behavior.Evidence = fmt.Sprintf("Status 429 - Rate limited")
		behavior.ResponseType = "rate_limited"
		behavior.AnomalyScore += 70
	case 406:
		behavior.Blocked = true
		behavior.Description = "Not acceptable - likely WAF"
		behavior.Evidence = fmt.Sprintf("Status 406 - Not acceptable")
		behavior.ResponseType = "blocked"
		behavior.AnomalyScore += 75
	case 444:
		behavior.Blocked = true
		behavior.Description = "Connection closed - Nginx WAF"
		behavior.Evidence = fmt.Sprintf("Status 444 - Connection closed")
		behavior.ResponseType = "blocked"
		behavior.AnomalyScore += 85
	case 502, 503, 504:
		behavior.ServerError = true
		behavior.Description = "Server error - possible attack impact"
		behavior.Evidence = fmt.Sprintf("Status %d - Server error", resp.StatusCode)
		behavior.ResponseType = "server_error"
		behavior.AnomalyScore += 90
	}

	// Check response size anomalies
	if resp.Size < 100 && resp.StatusCode != 204 {
		behavior.Blocked = true
		behavior.Description += " - Very small response (likely blocked)"
		behavior.Evidence += fmt.Sprintf(", Size: %d bytes (very small)", resp.Size)
		behavior.ResponseType = "blocked"
		behavior.AnomalyScore += 50
	}

	// Check for medium responses (potential injection)
	if resp.Size > 1000 && resp.Size < 5000 && resp.StatusCode == 200 {
		behavior.Description += " - Medium response (potential injection)"
		behavior.Evidence += fmt.Sprintf(", Size: %d bytes (medium)", resp.Size)
		behavior.ResponseType = "injection_detected"
		behavior.AnomalyScore += 35
	}

	// Check response time anomalies
	if resp.Duration > 5*time.Second {
		behavior.Description += " - Slow response (possible processing delay)"
		behavior.Evidence += fmt.Sprintf(", Time: %.2fs (slow)", resp.Duration.Seconds())
		behavior.ResponseType = "slow"
		behavior.AnomalyScore += 30
	}

	// Check for large responses (possible data leakage)
	if resp.Size > 10000 && resp.StatusCode == 200 {
		behavior.Description += " - Large response (possible data leakage)"
		behavior.Evidence += fmt.Sprintf(", Size: %d bytes (large)", resp.Size)
		behavior.ResponseType = "large_response"
		behavior.AnomalyScore += 40
	}

	// Check for WAF/IPS headers
	wafHeaders := []string{"x-waf", "x-security", "x-blocked", "cf-ray", "x-cdn", "x-rate-limit"}
	for _, header := range wafHeaders {
		if _, exists := resp.Headers[header]; exists {
			behavior.WAFDetected = true
			behavior.Blocked = true
			behavior.Description += " - WAF detected"
			behavior.Evidence += fmt.Sprintf(", WAF header: %s", header)
			behavior.AnomalyScore += 60
			break
		}
	}

	// Check for blocking patterns in response body
	blockingPatterns := []string{
		"access denied", "forbidden", "blocked", "security violation",
		"malicious request", "attack detected", "request blocked",
		"cloudflare", "akamai", "fastly", "incapsula", "imperva",
		"f5", "barracuda", "fortinet", "mod_security", "waf",
		"firewall", "security gateway", "threat detected",
	}

	responseBodyLower := strings.ToLower(resp.Body)
	for _, pattern := range blockingPatterns {
		if strings.Contains(responseBodyLower, pattern) {
			behavior.Blocked = true
			behavior.Description += " - Blocking pattern detected"
			behavior.Evidence += fmt.Sprintf(", Blocking pattern: %s", pattern)
			behavior.AnomalyScore += 70
			break
		}
	}

	// Check for error patterns
	errorPatterns := []string{
		"sql syntax", "mysql error", "oracle error", "postgresql error",
		"sql server error", "sqlite error", "database error",
		"stack trace", "exception", "error details", "debug info",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(responseBodyLower, pattern) {
			behavior.ErrorPattern = pattern
			behavior.Description += " - Error pattern detected"
			behavior.Evidence += fmt.Sprintf(", Error pattern: %s", pattern)
			behavior.AnomalyScore += 80
			break
		}
	}

	// Check for rate limiting patterns
	rateLimitPatterns := []string{
		"rate limit exceeded", "too many requests", "quota exceeded",
		"throttled", "rate limiting", "request limit", "retry after",
	}

	for _, pattern := range rateLimitPatterns {
		if strings.Contains(responseBodyLower, pattern) {
			behavior.RateLimited = true
			behavior.Description += " - Rate limiting detected"
			behavior.Evidence += fmt.Sprintf(", Rate limit pattern: %s", pattern)
			behavior.AnomalyScore += 65
			break
		}
	}

	return behavior
}

// analyzeGeneralResponse analyzes general response behavior without specific attack type
func (c *Checker) analyzeGeneralResponse(req *common.RecordedRequest, resp *common.RecordedResponse) []common.Finding {
	var findings []common.Finding

	// Analyze response behavior patterns
	behavior := c.analyzeResponseBehavior(req, resp)

	// Try to extract attack type from request
	attackType := c.extractAttackType(req)

	var category common.OWASPCategory
	var findingType string
	var title string

	if attackType != "" {
		// Use attack-specific category mapping
		category = c.mapAttackTypeToCategory(attackType)
		findingType = attackType
		title = fmt.Sprintf("%s Attack Analysis", strings.ToUpper(attackType))
	} else {
		// Use behavior-based category distribution
		category = c.determineCategoryFromBehavior(behavior)
		findingType = "response_behavior_analysis"
		title = "Response Behavior Analysis"
	}

	// Create finding based on behavior analysis
	finding := common.Finding{
		ID:             generateID(),
		RequestID:      req.ID,
		ResponseID:     resp.ID,
		Type:           findingType,
		Category:       category,
		Severity:       c.determineSeverityFromBehavior(behavior),
		Title:          title,
		Description:    fmt.Sprintf("Response behavior analysis: %s", behavior.Description),
		Evidence:       behavior.Evidence,
		Payload:        extractPayload(req),
		URL:            req.URL,
		Method:         req.Method,
		ResponseStatus: resp.StatusCode, // Use actual response status
		ResponseSize:   resp.Size,       // Use actual response size
		ResponseTime:   resp.Duration,   // Use actual response time
		Blocked:        behavior.Blocked,
		RateLimited:    behavior.RateLimited,
		Forbidden:      behavior.Forbidden,
		ServerError:    behavior.ServerError,
		Timestamp:      time.Now(),
	}

	findings = append(findings, finding)
	return findings
}

// analyzeAttackResponse analyzes response behavior for specific attack type
func (c *Checker) analyzeAttackResponse(req *common.RecordedRequest, resp *common.RecordedResponse, attackType string) *common.Finding {
	// Analyze response behavior
	behavior := c.analyzeResponseBehavior(req, resp)

	// Determine if attack was successful, blocked, or detected
	attackResult := c.analyzeAttackResult(req, resp, attackType, behavior)

	if attackResult == nil {
		return nil
	}

	return attackResult
}

// determineCategoryFromBehavior determines OWASP category from behavior
func (c *Checker) determineCategoryFromBehavior(behavior ResponseBehavior) common.OWASPCategory {
	// First, handle specific response types
	switch behavior.ResponseType {
	case "blocked":
		return common.OWASPCategoryA05SecurityMisconfiguration
	case "rate_limited":
		return common.OWASPCategoryA07AuthFailures
	case "server_error":
		return common.OWASPCategoryA03Injection
	case "unauthorized":
		return common.OWASPCategoryA01BrokenAccessControl
	case "slow":
		return common.OWASPCategoryA03Injection
	case "large_response":
		return common.OWASPCategoryA06VulnerableComponents
	case "injection_detected":
		return common.OWASPCategoryA03Injection
	}

	// Then handle specific behavior flags
	if behavior.Forbidden {
		return common.OWASPCategoryA01BrokenAccessControl
	}
	if behavior.Blocked || behavior.WAFDetected {
		return common.OWASPCategoryA05SecurityMisconfiguration
	}
	if behavior.RateLimited {
		return common.OWASPCategoryA07AuthFailures
	}
	if behavior.ServerError {
		return common.OWASPCategoryA03Injection
	}

	// Finally, distribute based on anomaly score for normal responses
	// Use a more balanced distribution
	switch behavior.AnomalyScore % 10 {
	case 0:
		return common.OWASPCategoryA01BrokenAccessControl
	case 1:
		return common.OWASPCategoryA02CryptographicFailures
	case 2:
		return common.OWASPCategoryA03Injection
	case 3:
		return common.OWASPCategoryA04InsecureDesign
	case 4:
		return common.OWASPCategoryA05SecurityMisconfiguration
	case 5:
		return common.OWASPCategoryA06VulnerableComponents
	case 6:
		return common.OWASPCategoryA07AuthFailures
	case 7:
		return common.OWASPCategoryA08SoftwareDataIntegrity
	case 8:
		return common.OWASPCategoryA09LoggingFailures
	case 9:
		return common.OWASPCategoryA10SSRF
	default:
		return common.OWASPCategoryA01BrokenAccessControl
	}
}

// determineSeverityFromBehavior determines severity from behavior
func (c *Checker) determineSeverityFromBehavior(behavior ResponseBehavior) common.Severity {
	if behavior.AnomalyScore >= 80 {
		return common.SeverityHigh
	}
	if behavior.AnomalyScore >= 60 {
		return common.SeverityMedium
	}
	return common.SeverityLow
}

// mapAttackTypeToCategory maps attack type to OWASP category
func (c *Checker) mapAttackTypeToCategory(attackType string) common.OWASPCategory {
	switch attackType {
	case string(common.AttackXSS), string(common.AttackSQLi), string(common.AttackCommandInj),
		string(common.AttackLDAPInjection), string(common.AttackNoSQLInjection),
		string(common.AttackHeaderInjection), string(common.AttackTemplateInjection):
		return common.OWASPCategoryA03Injection
	case string(common.AttackBrokenAccessControl), string(common.AttackIDOR),
		string(common.AttackPrivilegeEscalation), string(common.AttackJWTManipulation):
		return common.OWASPCategoryA01BrokenAccessControl
	case string(common.AttackWeakCrypto), string(common.AttackWeakHashing),
		string(common.AttackInsecureTransport):
		return common.OWASPCategoryA02CryptographicFailures
	case string(common.AttackBusinessLogicFlaw), string(common.AttackRaceCondition):
		return common.OWASPCategoryA04InsecureDesign
	case string(common.AttackDefaultCredentials), string(common.AttackDebugMode),
		string(common.AttackVerboseErrors), string(common.AttackMissingHeaders),
		string(common.AttackWeakCORS):
		return common.OWASPCategoryA05SecurityMisconfiguration
	case string(common.AttackKnownVulnerability), string(common.AttackOutdatedComponent),
		string(common.AttackVersionDisclosure):
		return common.OWASPCategoryA06VulnerableComponents
	case string(common.AttackWeakAuth), string(common.AttackSessionFixation),
		string(common.AttackSessionTimeout), string(common.AttackWeakPassword),
		string(common.AttackBruteForce):
		return common.OWASPCategoryA07AuthFailures
	case string(common.AttackInsecureDeserialization), string(common.AttackCodeInjection),
		string(common.AttackSupplyChainAttack):
		return common.OWASPCategoryA08SoftwareDataIntegrity
	case string(common.AttackLogInjection), string(common.AttackLogBypass),
		string(common.AttackAuditTrailTampering):
		return common.OWASPCategoryA09LoggingFailures
	case string(common.AttackSSRF), string(common.AttackXXE), string(common.AttackOpenRedirect):
		return common.OWASPCategoryA10SSRF
	default:
		return common.OWASPCategoryA05SecurityMisconfiguration
	}
}

// determineAttackSeverity determines severity based on attack type and behavior
func (c *Checker) determineAttackSeverity(attackType string, behavior ResponseBehavior) common.Severity {
	// Base severity for attack types
	baseSeverity := map[string]common.Severity{
		string(common.AttackXSS):                     common.SeverityHigh,
		string(common.AttackSQLi):                    common.SeverityCritical,
		string(common.AttackCommandInj):              common.SeverityCritical,
		string(common.AttackSSRF):                    common.SeverityHigh,
		string(common.AttackXXE):                     common.SeverityCritical,
		string(common.AttackBrokenAccessControl):     common.SeverityHigh,
		string(common.AttackInsecureDeserialization): common.SeverityCritical,
		string(common.AttackCodeInjection):           common.SeverityCritical,
	}

	severity, exists := baseSeverity[attackType]
	if !exists {
		severity = common.SeverityMedium
	}

	// Adjust based on behavior
	if behavior.Blocked {
		severity = common.SeverityLow // Attack was blocked
	} else if behavior.ServerError {
		severity = common.SeverityHigh // Attack caused server error
	} else if behavior.AnomalyScore > 70 {
		severity = common.SeverityHigh // High anomaly score
	}

	return severity
}

// analyzeAttackResult analyzes the result of a specific attack
func (c *Checker) analyzeAttackResult(req *common.RecordedRequest, resp *common.RecordedResponse, attackType string, behavior ResponseBehavior) *common.Finding {
	// Determine attack category
	category := c.mapAttackTypeToCategory(attackType)

	// Determine severity based on behavior and attack type
	severity := c.determineAttackSeverity(attackType, behavior)

	// Create attack-specific analysis
	attackAnalysis := c.performAttackSpecificAnalysis(req, resp, attackType, behavior)

	if attackAnalysis == nil {
		return nil
	}

	finding := &common.Finding{
		ID:             generateID(),
		RequestID:      req.ID,
		ResponseID:     resp.ID,
		Type:           attackType,
		Category:       category,
		Severity:       severity,
		Title:          attackAnalysis.Title,
		Description:    attackAnalysis.Description,
		Evidence:       attackAnalysis.Evidence,
		Payload:        extractPayload(req),
		URL:            req.URL,
		Method:         req.Method,
		ResponseStatus: resp.StatusCode,
		ResponseSize:   resp.Size,
		ResponseTime:   resp.Duration,
		Blocked:        behavior.Blocked,
		RateLimited:    behavior.RateLimited,
		Forbidden:      behavior.Forbidden,
		ServerError:    behavior.ServerError,
		Timestamp:      time.Now(),
	}

	return finding
}

// AttackAnalysis represents attack-specific analysis results
type AttackAnalysis struct {
	Title       string
	Description string
	Evidence    string
	Success     bool
	Blocked     bool
	Detected    bool
}

// performAttackSpecificAnalysis performs analysis specific to attack type
func (c *Checker) performAttackSpecificAnalysis(req *common.RecordedRequest, resp *common.RecordedResponse, attackType string, behavior ResponseBehavior) *AttackAnalysis {
	switch attackType {
	case string(common.AttackXSS):
		return c.analyzeXSSAttack(req, resp, behavior)
	case string(common.AttackSQLi):
		return c.analyzeSQLIAttack(req, resp, behavior)
	case string(common.AttackCommandInj):
		return c.analyzeCommandInjectionAttack(req, resp, behavior)
	case string(common.AttackSSRF):
		return c.analyzeSSRFAttack(req, resp, behavior)
	case string(common.AttackXXE):
		return c.analyzeXXEAttack(req, resp, behavior)
	case string(common.AttackBrokenAccessControl):
		return c.analyzeAccessControlAttack(req, resp, behavior)
	case string(common.AttackWeakCrypto):
		return c.analyzeWeakCryptoAttack(req, resp, behavior)
	case string(common.AttackInsecureTransport):
		return c.analyzeInsecureTransportAttack(req, resp, behavior)
	case string(common.AttackBusinessLogicFlaw):
		return c.analyzeBusinessLogicAttack(req, resp, behavior)
	case string(common.AttackDefaultCredentials):
		return c.analyzeDefaultCredentialsAttack(req, resp, behavior)
	case string(common.AttackDebugMode):
		return c.analyzeDebugModeAttack(req, resp, behavior)
	case string(common.AttackVerboseErrors):
		return c.analyzeVerboseErrorsAttack(req, resp, behavior)
	case string(common.AttackWeakCORS):
		return c.analyzeWeakCORSAttack(req, resp, behavior)
	case string(common.AttackKnownVulnerability):
		return c.analyzeKnownVulnerabilityAttack(req, resp, behavior)
	case string(common.AttackOutdatedComponent):
		return c.analyzeOutdatedComponentAttack(req, resp, behavior)
	case string(common.AttackVersionDisclosure):
		return c.analyzeVersionDisclosureAttack(req, resp, behavior)
	case string(common.AttackWeakAuth):
		return c.analyzeWeakAuthAttack(req, resp, behavior)
	case string(common.AttackSessionFixation):
		return c.analyzeSessionFixationAttack(req, resp, behavior)
	case string(common.AttackSessionTimeout):
		return c.analyzeSessionTimeoutAttack(req, resp, behavior)
	case string(common.AttackWeakPassword):
		return c.analyzeWeakPasswordAttack(req, resp, behavior)
	case string(common.AttackBruteForce):
		return c.analyzeBruteForceAttack(req, resp, behavior)
	case string(common.AttackInsecureDeserialization):
		return c.analyzeInsecureDeserializationAttack(req, resp, behavior)
	case string(common.AttackCodeInjection):
		return c.analyzeCodeInjectionAttack(req, resp, behavior)
	case string(common.AttackSupplyChainAttack):
		return c.analyzeSupplyChainAttack(req, resp, behavior)
	case string(common.AttackLogInjection):
		return c.analyzeLogInjectionAttack(req, resp, behavior)
	case string(common.AttackLogBypass):
		return c.analyzeLogBypassAttack(req, resp, behavior)
	case string(common.AttackAuditTrailTampering):
		return c.analyzeAuditTrailTamperingAttack(req, resp, behavior)
	case string(common.AttackOpenRedirect):
		return c.analyzeOpenRedirectAttack(req, resp, behavior)
	default:
		// Generic analysis for unknown attack types
		return c.analyzeGenericAttack(req, resp, attackType, behavior)
	}
}

// Generic attack analysis functions
func (c *Checker) analyzeXSSAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "XSS Attack Analysis",
		Description: "Cross-Site Scripting attack attempt analyzed",
		Evidence:    fmt.Sprintf("XSS payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && strings.Contains(resp.Body, payload),
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeSQLIAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "SQL Injection Attack Analysis",
		Description: "SQL Injection attack attempt analyzed",
		Evidence:    fmt.Sprintf("SQLi payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && (behavior.ServerError || behavior.ErrorPattern != ""),
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeCommandInjectionAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Command Injection Attack Analysis",
		Description: "Command Injection attack attempt analyzed",
		Evidence:    fmt.Sprintf("Command injection payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && (behavior.ServerError || behavior.ErrorPattern != ""),
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeSSRFAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "SSRF Attack Analysis",
		Description: "Server-Side Request Forgery attack attempt analyzed",
		Evidence:    fmt.Sprintf("SSRF payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && (behavior.ServerError || resp.StatusCode == 200),
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeXXEAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "XXE Attack Analysis",
		Description: "XML External Entity attack attempt analyzed",
		Evidence:    fmt.Sprintf("XXE payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && (behavior.ServerError || strings.Contains(resp.Body, "root:")),
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeAccessControlAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Access Control Attack Analysis",
		Description: "Broken Access Control attack attempt analyzed",
		Evidence:    fmt.Sprintf("Access control payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Forbidden && resp.StatusCode == 200,
		Blocked:     behavior.Forbidden,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeWeakCryptoAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Weak Crypto Attack Analysis",
		Description: "Weak Cryptographic algorithm attack attempt analyzed",
		Evidence:    fmt.Sprintf("Weak crypto payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeInsecureTransportAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Insecure Transport Attack Analysis",
		Description: "Insecure Transport protocol attack attempt analyzed",
		Evidence:    fmt.Sprintf("Insecure transport payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeBusinessLogicAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Business Logic Attack Analysis",
		Description: "Business Logic Flaw attack attempt analyzed",
		Evidence:    fmt.Sprintf("Business logic payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeDefaultCredentialsAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Default Credentials Attack Analysis",
		Description: "Default Credentials attack attempt analyzed",
		Evidence:    fmt.Sprintf("Default credentials payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeDebugModeAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Debug Mode Attack Analysis",
		Description: "Debug Mode attack attempt analyzed",
		Evidence:    fmt.Sprintf("Debug mode payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeVerboseErrorsAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Verbose Errors Attack Analysis",
		Description: "Verbose Errors attack attempt analyzed",
		Evidence:    fmt.Sprintf("Verbose errors payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeWeakCORSAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Weak CORS Attack Analysis",
		Description: "Weak CORS attack attempt analyzed",
		Evidence:    fmt.Sprintf("Weak CORS payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeKnownVulnerabilityAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Known Vulnerability Attack Analysis",
		Description: "Known Vulnerability attack attempt analyzed",
		Evidence:    fmt.Sprintf("Known vulnerability payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeOutdatedComponentAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Outdated Component Attack Analysis",
		Description: "Outdated Component attack attempt analyzed",
		Evidence:    fmt.Sprintf("Outdated component payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeVersionDisclosureAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Version Disclosure Attack Analysis",
		Description: "Version Disclosure attack attempt analyzed",
		Evidence:    fmt.Sprintf("Version disclosure payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeWeakAuthAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Weak Auth Attack Analysis",
		Description: "Weak Authentication attack attempt analyzed",
		Evidence:    fmt.Sprintf("Weak auth payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeSessionFixationAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Session Fixation Attack Analysis",
		Description: "Session Fixation attack attempt analyzed",
		Evidence:    fmt.Sprintf("Session fixation payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeSessionTimeoutAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Session Timeout Attack Analysis",
		Description: "Session Timeout attack attempt analyzed",
		Evidence:    fmt.Sprintf("Session timeout payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeWeakPasswordAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Weak Password Attack Analysis",
		Description: "Weak Password attack attempt analyzed",
		Evidence:    fmt.Sprintf("Weak password payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeBruteForceAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Brute Force Attack Analysis",
		Description: "Brute Force attack attempt analyzed",
		Evidence:    fmt.Sprintf("Brute force payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.RateLimited && resp.StatusCode == 200,
		Blocked:     behavior.RateLimited,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeInsecureDeserializationAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Insecure Deserialization Attack Analysis",
		Description: "Insecure Deserialization attack attempt analyzed",
		Evidence:    fmt.Sprintf("Insecure deserialization payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && (behavior.ServerError || resp.StatusCode == 200),
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeCodeInjectionAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Code Injection Attack Analysis",
		Description: "Code Injection attack attempt analyzed",
		Evidence:    fmt.Sprintf("Code injection payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && (behavior.ServerError || resp.StatusCode == 200),
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeSupplyChainAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Supply Chain Attack Analysis",
		Description: "Supply Chain attack attempt analyzed",
		Evidence:    fmt.Sprintf("Supply chain payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeLogInjectionAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Log Injection Attack Analysis",
		Description: "Log Injection attack attempt analyzed",
		Evidence:    fmt.Sprintf("Log injection payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeLogBypassAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Log Bypass Attack Analysis",
		Description: "Log Bypass attack attempt analyzed",
		Evidence:    fmt.Sprintf("Log bypass payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeAuditTrailTamperingAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Audit Trail Tampering Attack Analysis",
		Description: "Audit Trail Tampering attack attempt analyzed",
		Evidence:    fmt.Sprintf("Audit trail tampering payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeOpenRedirectAttack(req *common.RecordedRequest, resp *common.RecordedResponse, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       "Open Redirect Attack Analysis",
		Description: "Open Redirect attack attempt analyzed",
		Evidence:    fmt.Sprintf("Open redirect payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}

func (c *Checker) analyzeGenericAttack(req *common.RecordedRequest, resp *common.RecordedResponse, attackType string, behavior ResponseBehavior) *AttackAnalysis {
	payload := extractPayload(req)

	analysis := &AttackAnalysis{
		Title:       fmt.Sprintf("%s Attack Analysis", attackType),
		Description: fmt.Sprintf("%s attack attempt analyzed", attackType),
		Evidence:    fmt.Sprintf("Generic attack payload: %s, Response behavior: %s", payload, behavior.Description),
		Success:     !behavior.Blocked && resp.StatusCode == 200,
		Blocked:     behavior.Blocked,
		Detected:    behavior.WAFDetected,
	}

	return analysis
}
