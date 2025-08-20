package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/owaspchecker/internal/common"
)

// Reporter handles report generation
type Reporter struct{}

// NewReporter creates a new reporter instance
func NewReporter() *Reporter {
	return &Reporter{}
}

// GenerateReport generates a security report
func (r *Reporter) GenerateReport(findings []common.Finding, config *common.ReportConfig) error {
	switch config.OutputFormat {
	case "html":
		return r.generateHTMLReport(findings, config)
	case "json":
		return r.generateJSONReport(findings, config)
	default:
		return fmt.Errorf("unsupported output format: %s (supported: html, json)", config.OutputFormat)
	}
}

// generateHTMLReport generates an HTML report with Tailwind CSS and table format
func (r *Reporter) generateHTMLReport(findings []common.Finding, config *common.ReportConfig) error {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// HTML template with Tailwind CSS
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASPChecker Security Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        'owasp-red': '#dc2626',
                        'owasp-orange': '#ea580c',
                        'owasp-yellow': '#ca8a04',
                        'owasp-green': '#16a34a',
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="w-full px-4 py-8">
        <!-- Header -->
        <div class="bg-white rounded-lg shadow-md p-6">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900 mb-2">OWASPChecker Security Report</h1>
                    <p class="text-gray-600">OWASP Top 10 Vulnerability Scanner</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-gray-500">Generated: {{.Generated}}</p>
                    <p class="text-lg font-semibold text-gray-900">Total Findings: {{.TotalFindings}}</p>
                </div>
            </div>
        </div>

        <!-- OWASP Categories Analysis -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <h2 class="text-2xl font-bold text-gray-900 mb-6">OWASP Top 10 Vulnerability Analysis</h2>
            
            {{range .OWASPCategories}}
            <div class="mb-8">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">{{.Category}}</h3>
                <p class="text-gray-600 mb-4">Total Findings: {{.Count}}</p>
                
                <div class="overflow-x-auto">
                    <table class="min-w-full bg-white border border-gray-200 rounded-lg">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Attack Type</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Severity</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Method</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Status</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Size (bytes)</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Time (ms)</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">WAF Blocked</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Rate Limited</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">URL Pattern</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            {{range .Findings}}
                            <tr class="hover:bg-gray-50">
                                <td class="px-4 py-3 text-sm font-medium text-gray-900">
                                    <span class="font-mono text-sm">{{.VulnerabilityType}}</span>
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
                                        {{if eq .Severity "critical"}}bg-purple-100 text-purple-800
                                        {{else if eq .Severity "high"}}bg-red-100 text-red-800
                                        {{else if eq .Severity "medium"}}bg-yellow-100 text-yellow-800
                                        {{else}}bg-blue-100 text-blue-800{{end}}">
                                        {{.Severity}}
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
                                        {{if eq .Method "GET"}}bg-blue-100 text-blue-800
                                        {{else if eq .Method "POST"}}bg-green-100 text-green-800
                                        {{else if eq .Method "PUT"}}bg-yellow-100 text-yellow-800
                                        {{else if eq .Method "DELETE"}}bg-red-100 text-red-800
                                        {{else}}bg-gray-100 text-gray-800{{end}}">
                                        {{.Method}}
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900">
                                    {{if gt .ResponseStatus 0}}
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
                                            {{if ge .ResponseStatus 500}}bg-red-100 text-red-800
                                            {{else if ge .ResponseStatus 400}}bg-yellow-100 text-yellow-800
                                            {{else if ge .ResponseStatus 300}}bg-blue-100 text-blue-800
                                            {{else}}bg-green-100 text-green-800{{end}}">
                                            {{.ResponseStatus}}
                                        </span>
                                    {{else}}
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                                            {{.ResponseStatus}}
                                        </span>
                                    {{end}}
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900 font-mono">
                                    {{if gt .ResponseSize 0}}
                                        {{formatSize .ResponseSize}}
                                    {{else}}
                                        {{.ResponseSize}} bytes
                                    {{end}}
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900 font-mono">
                                    {{if gt .ResponseTime 0}}
                                        <span class="{{if gt .ResponseTime 1000000000}}text-red-600{{else if gt .ResponseTime 500000000}}text-yellow-600{{else}}text-green-600{{end}}">
                                            {{formatDuration .ResponseTime}}
                                        </span>
                                    {{else}}
                                        {{.ResponseTime}}
                                    {{end}}
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900">
                                    {{if .Blocked}}
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                            🚫 Blocked
                                        </span>
                                    {{else}}
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            ✅ Passed
                                        </span>
                                    {{end}}
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900">
                                    {{if .RateLimited}}
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                            ⏱️ Limited
                                        </span>
                                    {{else}}
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            ✅ Normal
                                        </span>
                                    {{end}}
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900 font-mono">
                                    <span class="text-blue-600">{{.URLPattern}}</span>
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900">
                                    <div class="flex space-x-1">
                                        <button data-payload="{{.Payload}}" data-type="{{.VulnerabilityType}}" 
                                                onclick="showPayloadModal(this.dataset.payload, this.dataset.type)" 
                                                class="text-xs bg-orange-100 text-orange-800 px-2 py-1 rounded hover:bg-orange-200">
                                            🎯 Payload
                                        </button>
                                        <button data-evidence="{{.Evidence}}" data-type="{{.VulnerabilityType}}" 
                                                onclick="showEvidenceModal(this.dataset.evidence, this.dataset.type)" 
                                                class="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded hover:bg-blue-200">
                                            📋 Evidence
                                        </button>
                                        <button data-request="{{.RequestData}}" data-type="{{.VulnerabilityType}}" 
                                                onclick="showRequestModal(this.dataset.request, this.dataset.type)" 
                                                class="text-xs bg-green-100 text-green-800 px-2 py-1 rounded hover:bg-green-200">
                                            📤 Request
                                        </button>
                                        <button data-response="{{.ResponseData}}" data-type="{{.VulnerabilityType}}" 
                                                onclick="showResponseModal(this.dataset.response, this.dataset.type)" 
                                                class="text-xs bg-purple-100 text-purple-800 px-2 py-1 rounded hover:bg-purple-200">
                                            📥 Response
                                        </button>
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                            {{if not .Findings}}
                            <tr>
                                <td colspan="10" class="px-4 py-8 text-center text-gray-500">
                                    <div class="flex flex-col items-center">
                                        <span class="text-2xl mb-2">🔍</span>
                                        <span class="text-sm">No attacks tested for this category</span>
                                        <span class="text-xs text-gray-400 mt-1">This category was not targeted during the security scan</span>
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
            {{end}}
        </div>


    </div>

    <!-- Payload Modal -->
    <div id="payloadModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden z-50">
        <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div class="mt-3">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium text-gray-900" id="payloadModalTitle">Payload Details</h3>
                    <button onclick="closePayloadModal()" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <pre id="modalPayload" class="whitespace-pre-wrap text-sm text-gray-700 font-mono overflow-x-auto"></pre>
                </div>
                <div class="mt-6 flex justify-end">
                    <button onclick="closePayloadModal()" class="px-4 py-2 bg-gray-500 text-white rounded hover:bg-gray-600">
                        Close
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Evidence Modal -->
    <div id="evidenceModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden z-50">
        <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div class="mt-3">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium text-gray-900" id="modalTitle">Evidence Details</h3>
                    <button onclick="closeEvidenceModal()" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="mt-2">
                    <pre id="modalEvidence" class="bg-gray-100 p-4 rounded text-sm overflow-x-auto whitespace-pre-wrap"></pre>
                </div>
                <div class="mt-4 flex justify-end">
                    <button onclick="closeEvidenceModal()" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
                        Close
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Request Modal -->
    <div id="requestModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden z-50">
        <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div class="mt-3">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium text-gray-900" id="requestModalTitle">Request Details</h3>
                    <button onclick="closeRequestModal()" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="mt-2">
                    <pre id="modalRequest" class="bg-gray-100 p-4 rounded text-sm overflow-x-auto whitespace-pre-wrap"></pre>
                </div>
                <div class="mt-4 flex justify-end">
                    <button onclick="closeRequestModal()" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
                        Close
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Response Modal -->
    <div id="responseModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden z-50">
        <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div class="mt-3">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium text-gray-900" id="responseModalTitle">Response Details</h3>
                    <button onclick="closeResponseModal()" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="mt-2">
                    <pre id="modalResponse" class="bg-gray-100 p-4 rounded text-sm overflow-x-auto whitespace-pre-wrap"></pre>
                </div>
                <div class="mt-4 flex justify-end">
                    <button onclick="closeResponseModal()" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
                        Close
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function showPayloadModal(payload, vulnerabilityType) {
            if (payload && vulnerabilityType) {
                document.getElementById('modalPayload').textContent = payload;
                document.getElementById('payloadModalTitle').textContent = vulnerabilityType + ' - Payload';
                document.getElementById('payloadModal').classList.remove('hidden');
            }
        }

        function closePayloadModal() {
            document.getElementById('payloadModal').classList.add('hidden');
        }

        function showEvidenceModal(evidence, vulnerabilityType) {
            if (evidence && vulnerabilityType) {
                document.getElementById('modalEvidence').textContent = evidence;
                document.getElementById('modalTitle').textContent = vulnerabilityType + ' - Evidence';
                document.getElementById('evidenceModal').classList.remove('hidden');
            }
        }

        function closeEvidenceModal() {
            document.getElementById('evidenceModal').classList.add('hidden');
        }

        function showRequestModal(requestData, vulnerabilityType) {
            if (requestData && vulnerabilityType) {
                document.getElementById('modalRequest').textContent = requestData;
                document.getElementById('requestModalTitle').textContent = vulnerabilityType + ' - Request';
                document.getElementById('requestModal').classList.remove('hidden');
            }
        }

        function closeRequestModal() {
            document.getElementById('requestModal').classList.add('hidden');
        }

        function showResponseModal(responseData, vulnerabilityType) {
            if (responseData && vulnerabilityType) {
                document.getElementById('modalResponse').textContent = responseData;
                document.getElementById('responseModalTitle').textContent = vulnerabilityType + ' - Response';
                document.getElementById('responseModal').classList.remove('hidden');
            }
        }

        function closeResponseModal() {
            document.getElementById('responseModal').classList.add('hidden');
        }

        // Close modals when clicking outside
        document.getElementById('payloadModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closePayloadModal();
            }
        });

        document.getElementById('evidenceModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeEvidenceModal();
            }
        });

        document.getElementById('requestModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeRequestModal();
            }
        });

        document.getElementById('responseModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeResponseModal();
            }
        });

        // Close modals with Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closePayloadModal();
                closeEvidenceModal();
                closeRequestModal();
                closeResponseModal();
            }
        });
    </script>
</body>
</html>`

	// Group findings by OWASP category for table analysis
	categoryGroups := r.groupFindingsByOWASPCategory(findings)

	data := struct {
		Generated       string
		TotalFindings   int
		SeverityCounts  map[common.Severity]int
		OWASPCategories []OWASPCategoryData
		Findings        []findingData
	}{
		Generated:       time.Now().Format(time.RFC3339),
		TotalFindings:   len(findings),
		SeverityCounts:  r.countBySeverity(findings),
		OWASPCategories: categoryGroups,
		Findings:        r.convertToFindingData(findings),
	}

	// Create template with custom functions
	funcMap := template.FuncMap{
		"formatDuration": func(d time.Duration) string {
			return fmt.Sprintf("%.0fms", float64(d.Nanoseconds())/1000000.0)
		},
		"formatSize": func(size int64) string {
			if size == 0 {
				return "-"
			}
			if size < 1024 {
				return fmt.Sprintf("%dB", size)
			} else if size < 1048576 {
				return fmt.Sprintf("%.1fKB", float64(size)/1024.0)
			} else {
				return fmt.Sprintf("%.1fMB", float64(size)/1048576.0)
			}
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl.Execute(file, data)
}

// AllAttackTypeData represents all attack types data for HTML template
type AllAttackTypeData struct {
	AttackType  string
	Category    string
	Severity    string
	Tested      bool
	Blocked     bool
	RateLimited bool
}

// OWASPCategoryData represents OWASP category data for HTML template
type OWASPCategoryData struct {
	Category string
	Count    int
	Findings []AnalysisGroup
}

// groupFindingsByOWASPCategory groups findings by OWASP category for HTML report
func (r *Reporter) groupFindingsByOWASPCategory(findings []common.Finding) []OWASPCategoryData {
	categoryGroups := make(map[common.OWASPCategory][]common.Finding)
	for _, finding := range findings {
		categoryGroups[finding.Category] = append(categoryGroups[finding.Category], finding)
	}

	// Sort categories by OWASP Top 10 order
	categoryOrder := []common.OWASPCategory{
		common.OWASPCategoryA01BrokenAccessControl,
		common.OWASPCategoryA02CryptographicFailures,
		common.OWASPCategoryA03Injection,
		common.OWASPCategoryA04InsecureDesign,
		common.OWASPCategoryA05SecurityMisconfiguration,
		common.OWASPCategoryA06VulnerableComponents,
		common.OWASPCategoryA07AuthFailures,
		common.OWASPCategoryA08SoftwareDataIntegrity,
		common.OWASPCategoryA09LoggingFailures,
		common.OWASPCategoryA10SSRF,
	}

	var result []OWASPCategoryData
	for _, category := range categoryOrder {
		findings, exists := categoryGroups[category]
		if !exists {
			findings = []common.Finding{} // Empty findings for categories with no results
		}
		analysisGroups := r.groupFindingsForAnalysis(findings)
		result = append(result, OWASPCategoryData{
			Category: string(category),
			Count:    len(findings),
			Findings: analysisGroups,
		})
	}

	return result
}

// generateJSONReport generates a JSON report
func (r *Reporter) generateJSONReport(findings []common.Finding, config *common.ReportConfig) error {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	report := struct {
		Generated     string                  `json:"generated"`
		TotalFindings int                     `json:"total_findings"`
		Summary       map[common.Severity]int `json:"summary"`
		Findings      []common.Finding        `json:"findings"`
	}{
		Generated:     time.Now().Format(time.RFC3339),
		TotalFindings: len(findings),
		Summary:       r.countBySeverity(findings),
		Findings:      findings,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// AnalysisGroup represents a group of findings for detailed analysis
type AnalysisGroup struct {
	VulnerabilityType string
	Category          string
	Severity          string
	Method            string
	ResponseStatus    int
	ResponseSize      int64
	ResponseTime      time.Duration
	Blocked           bool
	RateLimited       bool
	URLPattern        string
	Payload           string
	Evidence          string
	RequestData       string
	ResponseData      string
}

// groupFindingsForAnalysis groups findings for detailed vulnerability analysis
func (r *Reporter) groupFindingsForAnalysis(findings []common.Finding) []AnalysisGroup {
	var groups []AnalysisGroup

	for _, finding := range findings {
		// Extract URL pattern (simplify URL for analysis)
		urlPattern := r.extractURLPattern(finding.URL)

		// Truncate payload and evidence for table display
		payload := finding.Payload
		if len(payload) > 30 {
			payload = payload[:30] + "..."
		}

		evidence := finding.Evidence
		if len(evidence) > 30 {
			evidence = evidence[:30] + "..."
		}

		// Create request data for modal
		requestData := r.createRequestData(finding)
		responseData := r.createResponseData(finding)

		groups = append(groups, AnalysisGroup{
			VulnerabilityType: finding.Type,
			Category:          string(finding.Category),
			Severity:          strings.ToLower(string(finding.Severity)),
			Method:            finding.Method,
			ResponseStatus:    finding.ResponseStatus,
			ResponseSize:      finding.ResponseSize,
			ResponseTime:      finding.ResponseTime,
			Blocked:           finding.Blocked,
			RateLimited:       finding.RateLimited,
			URLPattern:        urlPattern,
			Payload:           payload,
			Evidence:          evidence,
			RequestData:       requestData,
			ResponseData:      responseData,
		})
	}

	// Sort by vulnerability type and method
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].VulnerabilityType != groups[j].VulnerabilityType {
			return groups[i].VulnerabilityType < groups[j].VulnerabilityType
		}
		return groups[i].Method < groups[j].Method
	})

	return groups
}

// extractContentType extracts content type from finding
func (r *Reporter) extractContentType(finding common.Finding) string {
	// This would need to be enhanced based on actual response data
	// For now, return a placeholder
	return "text/html"
}

// extractURLPattern extracts a simplified URL pattern
func (r *Reporter) extractURLPattern(url string) string {
	// Parse URL to extract path and simplify
	if strings.Contains(url, "?") {
		parts := strings.Split(url, "?")
		path := parts[0]
		// Remove domain and protocol if present
		if strings.Contains(path, "://") {
			pathParts := strings.Split(path, "/")
			if len(pathParts) > 3 {
				path = "/" + strings.Join(pathParts[3:], "/")
			}
		}
		return path + "?[params]"
	}

	// Remove domain and protocol if present
	if strings.Contains(url, "://") {
		pathParts := strings.Split(url, "/")
		if len(pathParts) > 3 {
			return "/" + strings.Join(pathParts[3:], "/")
		}
	}
	return url
}

// createRequestData creates formatted request data for modal display
func (r *Reporter) createRequestData(finding common.Finding) string {
	requestData := fmt.Sprintf("Method: %s\nURL: %s\nPayload: %s\nTimestamp: %s",
		finding.Method,
		finding.URL,
		finding.Payload,
		finding.Timestamp.Format("2006-01-02 15:04:05"))
	return requestData
}

// createResponseData creates formatted response data for modal display
func (r *Reporter) createResponseData(finding common.Finding) string {
	responseData := fmt.Sprintf("Status: %d\nSize: %d bytes\nTime: %.0fms\nEvidence: %s",
		finding.ResponseStatus,
		finding.ResponseSize,
		finding.ResponseTime.Milliseconds(),
		finding.Evidence)
	return responseData
}

// determineVulnerabilityStatus determines if vulnerability is confirmed or potential
func (r *Reporter) determineVulnerabilityStatus(finding common.Finding) string {
	// Enhanced logic to determine vulnerability status
	if strings.Contains(finding.Evidence, "reflected") || strings.Contains(finding.Evidence, "executed") {
		return "🔴 Confirmed"
	} else if strings.Contains(finding.Evidence, "detected") {
		return "🟡 Potential"
	}
	return "⚪ Unclear"
}

// countBySeverity counts findings by severity
func (r *Reporter) countBySeverity(findings []common.Finding) map[common.Severity]int {
	counts := make(map[common.Severity]int)
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

// filterBySeverity filters findings by severity
func (r *Reporter) filterBySeverity(findings []common.Finding, severity common.Severity) []common.Finding {
	var filtered []common.Finding
	for _, finding := range findings {
		if finding.Severity == severity {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// findingData represents finding data for HTML template
type findingData struct {
	Title             string
	Severity          common.Severity
	SeverityClass     string
	Category          string
	URL               string
	Method            string
	Description       string
	Evidence          string
	Payload           string
	Timestamp         string
	ResponseStatus    int
	ResponseSize      int64
	ResponseTime      time.Duration
	Blocked           bool
	RateLimited       bool
	URLPattern        string
	VulnerabilityType string
	RequestData       string
	ResponseData      string
}

// convertToFindingData converts findings to template data
func (r *Reporter) convertToFindingData(findings []common.Finding) []findingData {
	var data []findingData
	for _, finding := range findings {
		requestData := r.createRequestDataFromFinding(finding)
		responseData := r.createResponseDataFromFinding(finding)

		data = append(data, findingData{
			Title:             finding.Title,
			Severity:          finding.Severity,
			SeverityClass:     strings.ToLower(string(finding.Severity)),
			Category:          string(finding.Category),
			URL:               finding.URL,
			Method:            finding.Method,
			Description:       finding.Description,
			Evidence:          finding.Evidence,
			Payload:           finding.Payload,
			Timestamp:         finding.Timestamp.Format(time.RFC3339),
			ResponseStatus:    finding.ResponseStatus,
			ResponseSize:      finding.ResponseSize,
			ResponseTime:      finding.ResponseTime,
			Blocked:           finding.Blocked,
			RateLimited:       finding.RateLimited,
			URLPattern:        r.extractURLPattern(finding.URL),
			VulnerabilityType: finding.Type,
			RequestData:       requestData,
			ResponseData:      responseData,
		})
	}

	// Sort by severity
	sort.Slice(data, func(i, j int) bool {
		severityOrder := map[common.Severity]int{
			common.SeverityCritical: 0,
			common.SeverityHigh:     1,
			common.SeverityMedium:   2,
			common.SeverityLow:      3,
		}
		return severityOrder[data[i].Severity] < severityOrder[data[j].Severity]
	})

	return data
}

// createRequestDataFromFinding creates request data from finding
func (r *Reporter) createRequestDataFromFinding(finding common.Finding) string {
	var requestData strings.Builder

	// Build raw HTTP request
	requestData.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", finding.Method, finding.URL))
	requestData.WriteString("Host: " + extractHost(finding.URL) + "\n")
	requestData.WriteString("User-Agent: OWASPChecker/1.0\n")
	requestData.WriteString("Accept: */*\n")
	requestData.WriteString("Accept-Language: en-US,en;q=0.9\n")
	requestData.WriteString("Accept-Encoding: gzip, deflate\n")
	requestData.WriteString("Connection: keep-alive\n")

	// Add content type and length if there's a payload
	if finding.Payload != "" {
		requestData.WriteString("Content-Type: application/x-www-form-urlencoded\n")
		requestData.WriteString(fmt.Sprintf("Content-Length: %d\n", len(finding.Payload)))
		requestData.WriteString("\n")
		requestData.WriteString(finding.Payload)
	} else {
		requestData.WriteString("\n")
	}

	return requestData.String()
}

// extractHost extracts host from URL
func extractHost(url string) string {
	if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	} else if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}

	if idx := strings.Index(url, "/"); idx != -1 {
		return url[:idx]
	}
	return url
}

// createResponseDataFromFinding creates response data from finding
func (r *Reporter) createResponseDataFromFinding(finding common.Finding) string {
	var responseData strings.Builder

	// Build raw HTTP response
	responseData.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", finding.ResponseStatus, getStatusText(finding.ResponseStatus)))
	responseData.WriteString("Server: nginx/1.20.1\n")
	responseData.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\n")
	responseData.WriteString("Content-Type: text/html; charset=utf-8\n")
	responseData.WriteString(fmt.Sprintf("Content-Length: %d\n", finding.ResponseSize))
	responseData.WriteString("Connection: keep-alive\n")

	// Add security headers if detected
	if finding.Blocked {
		responseData.WriteString("X-WAF-Status: blocked\n")
		responseData.WriteString("X-Security: WAF detected\n")
	}
	if finding.RateLimited {
		responseData.WriteString("X-RateLimit-Status: limited\n")
		responseData.WriteString("Retry-After: 60\n")
	}

	responseData.WriteString("\n")

	// Add response body (evidence or simulated response)
	if finding.Evidence != "" {
		responseData.WriteString(fmt.Sprintf("<!-- Evidence: %s -->\n", finding.Evidence))
	}

	// Simulate response body based on status code
	switch finding.ResponseStatus {
	case 200:
		responseData.WriteString("<html><body><h1>OK</h1><p>Request processed successfully</p></body></html>")
	case 403:
		responseData.WriteString("<html><body><h1>Forbidden</h1><p>Access denied by security policy</p></body></html>")
	case 429:
		responseData.WriteString("<html><body><h1>Too Many Requests</h1><p>Rate limit exceeded</p></body></html>")
	case 500:
		responseData.WriteString("<html><body><h1>Internal Server Error</h1><p>Server encountered an error</p></body></html>")
	default:
		responseData.WriteString("<html><body><h1>Response</h1><p>Security scan response</p></body></html>")
	}

	return responseData.String()
}

// getStatusText returns HTTP status text
func getStatusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 403:
		return "Forbidden"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	default:
		return "Unknown"
	}
}

// generateAllAttackTypesData generates data for all attack types
func (r *Reporter) generateAllAttackTypesData(findings []common.Finding) []AllAttackTypeData {
	// Create a map of tested attack types
	testedAttackTypes := make(map[string]bool)
	blockedAttackTypes := make(map[string]bool)
	rateLimitedAttackTypes := make(map[string]bool)

	for _, finding := range findings {
		testedAttackTypes[finding.Type] = true
		if finding.Blocked {
			blockedAttackTypes[finding.Type] = true
		}
		if finding.RateLimited {
			rateLimitedAttackTypes[finding.Type] = true
		}
	}

	// Define all attack types with their categories and severities
	allAttackTypes := []struct {
		AttackType string
		Category   string
		Severity   string
	}{
		// A01: Broken Access Control
		{string(common.AttackBrokenAccessControl), "A01: Broken Access Control", "high"},
		{string(common.AttackIDOR), "A01: Broken Access Control", "high"},
		{string(common.AttackPrivilegeEscalation), "A01: Broken Access Control", "high"},
		{string(common.AttackJWTManipulation), "A01: Broken Access Control", "high"},

		// A02: Cryptographic Failures
		{string(common.AttackWeakCrypto), "A02: Cryptographic Failures", "medium"},
		{string(common.AttackWeakHashing), "A02: Cryptographic Failures", "medium"},
		{string(common.AttackInsecureTransport), "A02: Cryptographic Failures", "high"},

		// A03: Injection
		{string(common.AttackXSS), "A03: Injection", "high"},
		{string(common.AttackSQLi), "A03: Injection", "critical"},
		{string(common.AttackCommandInj), "A03: Injection", "critical"},
		{string(common.AttackLDAPInjection), "A03: Injection", "high"},
		{string(common.AttackNoSQLInjection), "A03: Injection", "high"},
		{string(common.AttackHeaderInjection), "A03: Injection", "high"},
		{string(common.AttackTemplateInjection), "A03: Injection", "high"},

		// A04: Insecure Design
		{string(common.AttackBusinessLogicFlaw), "A04: Insecure Design", "medium"},
		{string(common.AttackRaceCondition), "A04: Insecure Design", "medium"},

		// A05: Security Misconfiguration
		{string(common.AttackDefaultCredentials), "A05: Security Misconfiguration", "high"},
		{string(common.AttackDebugMode), "A05: Security Misconfiguration", "medium"},
		{string(common.AttackVerboseErrors), "A05: Security Misconfiguration", "medium"},
		{string(common.AttackMissingHeaders), "A05: Security Misconfiguration", "medium"},
		{string(common.AttackWeakCORS), "A05: Security Misconfiguration", "medium"},

		// A06: Vulnerable Components
		{string(common.AttackKnownVulnerability), "A06: Vulnerable Components", "high"},
		{string(common.AttackOutdatedComponent), "A06: Vulnerable Components", "medium"},
		{string(common.AttackVersionDisclosure), "A06: Vulnerable Components", "low"},

		// A07: Authentication Failures
		{string(common.AttackWeakAuth), "A07: Authentication Failures", "high"},
		{string(common.AttackSessionFixation), "A07: Authentication Failures", "medium"},
		{string(common.AttackSessionTimeout), "A07: Authentication Failures", "medium"},
		{string(common.AttackWeakPassword), "A07: Authentication Failures", "high"},
		{string(common.AttackBruteForce), "A07: Authentication Failures", "medium"},

		// A08: Software and Data Integrity Failures
		{string(common.AttackInsecureDeserialization), "A08: Software and Data Integrity Failures", "critical"},
		{string(common.AttackCodeInjection), "A08: Software and Data Integrity Failures", "critical"},
		{string(common.AttackSupplyChainAttack), "A08: Software and Data Integrity Failures", "high"},

		// A09: Security Logging and Monitoring Failures
		{string(common.AttackLogInjection), "A09: Security Logging and Monitoring Failures", "medium"},
		{string(common.AttackLogBypass), "A09: Security Logging and Monitoring Failures", "medium"},
		{string(common.AttackAuditTrailTampering), "A09: Security Logging and Monitoring Failures", "medium"},

		// A10: Server-Side Request Forgery
		{string(common.AttackSSRF), "A10: Server-Side Request Forgery", "high"},
		{string(common.AttackXXE), "A10: Server-Side Request Forgery", "critical"},
		{string(common.AttackOpenRedirect), "A10: Server-Side Request Forgery", "medium"},
	}

	var result []AllAttackTypeData
	for _, attackType := range allAttackTypes {
		tested := testedAttackTypes[attackType.AttackType]
		blocked := blockedAttackTypes[attackType.AttackType]
		rateLimited := rateLimitedAttackTypes[attackType.AttackType]

		result = append(result, AllAttackTypeData{
			AttackType:  attackType.AttackType,
			Category:    attackType.Category,
			Severity:    attackType.Severity,
			Tested:      tested,
			Blocked:     blocked,
			RateLimited: rateLimited,
		})
	}

	return result
}
