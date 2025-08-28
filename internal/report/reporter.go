package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/owaspattacksimulator/internal/common"
)

// Reporter handles report generation
type Reporter struct{}

// NewReporter creates a new reporter instance
func NewReporter() *Reporter {
	return &Reporter{}
}

// GenerateReport generates a security report
func (r *Reporter) GenerateReport(findings []common.Finding, config *common.ReportConfig, totalRequests int, scanDuration time.Duration) error {
	switch config.OutputFormat {
	case "html":
		return r.generateHTMLReport(findings, config, totalRequests, scanDuration)
	case "json":
		return r.generateJSONReport(findings, config)
	default:
		return fmt.Errorf("unsupported output format: %s (supported: html, json)", config.OutputFormat)
	}
}

// generateHTMLReport generates an HTML report with Tailwind CSS and table format
func (r *Reporter) generateHTMLReport(findings []common.Finding, config *common.ReportConfig, totalRequests int, scanDuration time.Duration) error {
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
    <title>OWASPAttackSimulator Security Report</title>
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
                    <h1 class="text-3xl font-bold text-gray-900 mb-2">OWASPAttackSimulator Security Report</h1>
                    <p class="text-gray-600">OWASP Top 10 Attack Simulator</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-gray-500">Generated: {{.Generated}}</p>
                    <p class="text-lg font-semibold text-gray-900">Total Findings: {{.TotalFindings}}</p>
                </div>
            </div>
        </div>

        <!-- Scan Summary -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <h2 class="text-2xl font-bold text-gray-900 mb-6">Scan Summary</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div class="bg-blue-50 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <svg class="h-8 w-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <p class="text-sm font-medium text-blue-600">Total Requests</p>
                            <p class="text-2xl font-bold text-blue-900">{{.TotalRequests}}</p>
                        </div>
                    </div>
                </div>
                <div class="bg-green-50 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <svg class="h-8 w-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <p class="text-sm font-medium text-green-600">Requests Tested</p>
                            <p class="text-2xl font-bold text-green-900">{{.TotalFindings}}</p>
                        </div>
                    </div>
                </div>
                <div class="bg-yellow-50 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <svg class="h-8 w-8 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                        <div class="ml-4">
                            <p class="text-sm font-medium text-yellow-600">Scan Duration</p>
                            <p class="text-2xl font-bold text-yellow-900">{{.ScanDuration}}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Category Based Analysis -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <h2 class="text-2xl font-bold text-gray-900 mb-6">All Requests Analysis</h2>
            <p class="text-gray-600 mb-4">Detailed analysis of all {{.TotalFindings}} requests tested during the security scan, organized by OWASP categories.</p>
            
            <!-- Category Filter -->
            <div class="mb-6 p-4 bg-gray-50 rounded-lg">
                <h3 class="text-lg font-semibold text-gray-800 mb-3">Filter by Category</h3>
                <div class="flex flex-wrap gap-4">
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-all" class="category-filter mr-2" checked>
                        <span class="text-sm font-medium text-gray-700">All Categories</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a01" class="category-filter mr-2" data-category="A01:2021 - Broken Access Control">
                        <span class="text-sm font-medium text-gray-700">A01:2021 - Broken Access Control</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a02" class="category-filter mr-2" data-category="A02:2021 - Cryptographic Failures">
                        <span class="text-sm font-medium text-gray-700">A02:2021 - Cryptographic Failures</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a03" class="category-filter mr-2" data-category="A03:2021 - Injection">
                        <span class="text-sm font-medium text-gray-700">A03:2021 - Injection</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a04" class="category-filter mr-2" data-category="A04:2021 - Insecure Design">
                        <span class="text-sm font-medium text-gray-700">A04:2021 - Insecure Design</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a05" class="category-filter mr-2" data-category="A05:2021 - Security Misconfiguration">
                        <span class="text-sm font-medium text-gray-700">A05:2021 - Security Misconfiguration</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a06" class="category-filter mr-2" data-category="A06:2021 - Vulnerable and Outdated Components">
                        <span class="text-sm font-medium text-gray-700">A06:2021 - Vulnerable and Outdated Components</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a07" class="category-filter mr-2" data-category="A07:2021 - Identification and Authentication Failures">
                        <span class="text-sm font-medium text-gray-700">A07:2021 - Identification and Authentication Failures</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a08" class="category-filter mr-2" data-category="A08:2021 - Software and Data Integrity Failures">
                        <span class="text-sm font-medium text-gray-700">A08:2021 - Software and Data Integrity Failures</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a09" class="category-filter mr-2" data-category="A09:2021 - Security Logging and Monitoring Failures">
                        <span class="text-sm font-medium text-gray-700">A09:2021 - Security Logging and Monitoring Failures</span>
                    </label>
                    <label class="flex items-center">
                        <input type="checkbox" id="filter-a10" class="category-filter mr-2" data-category="A10:2021 - Server-Side Request Forgery">
                        <span class="text-sm font-medium text-gray-700">A10:2021 - Server-Side Request Forgery</span>
                    </label>
                </div>
            </div>
            
            {{range .OWASPCategories}}
            <div class="mb-8 category-section" data-category="{{.Category | html}}">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">{{.Category | html}}</h3>
                <p class="text-gray-600 mb-4">Total Findings: {{.Count}}</p>
                
                {{if gt .Count 0}}
                <div class="overflow-x-auto">
                    <table class="min-w-full bg-white border border-gray-200 rounded-lg">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">#</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Timestamp</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Request Type</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Method</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">URL</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Status</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Size (bytes)</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Time (ms)</th>
                                <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider border-b">WAF Blocked</th>
                                <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Rate Limited</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-b">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            {{range $index, $finding := .Findings}}
                            <tr class="hover:bg-gray-50">
                                <td class="px-4 py-3 text-sm text-gray-900 font-mono">{{add $index 1}}</td>
                                <td class="px-4 py-3 text-sm text-gray-900 font-mono">
                                    <span class="text-xs">{{formatTimestamp .Timestamp}}</span>
                                </td>
                                <td class="px-4 py-3 text-sm font-medium text-gray-900">
                                    <span class="font-mono text-sm">{{.VulnerabilityType | html}}</span>
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
                                <td class="px-4 py-3 text-sm text-gray-900 font-mono">
                                    <div class="flex items-center space-x-2">
                                        <button onclick="showURLModal('{{.URL | html}}', '{{.VulnerabilityType | html}}')" 
                                                class="text-blue-600 hover:text-blue-800 hover:bg-blue-50 underline cursor-pointer truncate block max-w-xs text-left px-2 py-1 rounded border border-transparent hover:border-blue-300 transition-colors">
                                            {{.URL | html}}
                                        </button>
                                    </div>
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

                                <td class="px-4 py-3 text-sm text-gray-900 text-center">
                                    {{if .Blocked}}
                                    <span class="text-xs bg-red-100 text-red-800 px-2 py-1 rounded hover:bg-red-200">
                                            <span class="text-center">🚫</span>
                                            <span class="text-center">Blocked</span>
                                        </span>
                                    {{else}}
                                        <span class="text-xs bg-green-100 text-green-800 px-2 py-1 rounded hover:bg-green-200">
                                            <span class="text-center">✅</span>
                                            <span class="text-center">Passed</span>
                                        </span>
                                    {{end}}
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900 text-center">
                                    {{if .RateLimited}}
                                        <span class="text-xs bg-yellow-100 text-yellow-800 px-2 py-1 rounded hover:bg-yellow-200">
                                            <span class="text-center">⏱️</span>
                                            <span class="text-center">Limited</span>
                                        </span>
                                    {{else}}
                                        <span class="text-xs bg-green-100 text-green-800 px-2 py-1 rounded hover:bg-green-200">
                                            <span class="text-center">✅</span>
                                            <span class="text-center">Normal</span>
                                        </span>
                                    {{end}}
                                </td>
                                <td class="px-4 py-3 text-sm text-gray-900 text-center">
                                    <div class="flex space-x-1 justify-center">
                                        <button data-payload="{{.Payload | html}}" data-type="{{.VulnerabilityType | html}}" 
                                                onclick="showPayloadModal(this.dataset.payload, this.dataset.type)" 
                                                class="text-xs bg-orange-100 text-orange-800 px-2 py-1 rounded hover:bg-orange-200">
                                            <span class="text-center">🎯</span>
                                            <span class="text-center">Payload</span>
                                        </button>
                                        <button data-evidence="{{.Evidence | html}}" data-type="{{.VulnerabilityType | html}}" 
                                                onclick="showEvidenceModal(this.dataset.evidence, this.dataset.type)" 
                                                class="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded hover:bg-blue-200">
                                            <span class="text-center">📋</span>
                                            <span class="text-center">Evidence</span>
                                        </button>
                                        <button data-request="{{.RequestRaw | html}}" data-type="{{.VulnerabilityType | html}}" 
                                                onclick="showRequestModal(this.dataset.request, this.dataset.type)" 
                                                class="text-xs bg-green-100 text-green-800 px-2 py-1 rounded hover:bg-green-200">
                                            <span class="text-center">📤</span>
                                            <span class="text-center">Request</span>
                                        </button>
                                        <button data-response="{{.ResponseRaw | html}}" data-type="{{.VulnerabilityType | html}}" 
                                                onclick="showResponseModal(this.dataset.response, this.dataset.type)" 
                                                class="text-xs bg-purple-100 text-purple-800 px-2 py-1 rounded hover:bg-purple-200">
                                            <span class="text-center">📥</span>
                                            <span class="text-center">Response</span>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
                {{else}}
                <div class="text-center py-6">
                    <div class="inline-flex items-center justify-center w-12 h-12 bg-green-100 rounded-full mb-3">
                        <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                        </svg>
                    </div>
                    <p class="text-gray-600 text-sm">No findings in this category - all tests passed successfully.</p>
                </div>
                {{end}}
            </div>
            {{end}}
        </div>

        <!-- No Findings Message -->
        {{if eq .TotalFindings 0}}
        <div class="text-center py-12">
            <div class="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-4">
                <svg class="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
            </div>
            <h1 class="text-2xl font-bold text-gray-900 mb-2">Security Assessment Complete</h1>
            <p class="text-gray-600 mb-4">The comprehensive security scan has been completed. No security vulnerabilities or potential threats were identified during this assessment.</p>
        </div>
        {{end}}
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

    <!-- URL Modal -->
    <div id="urlModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden z-[9999]">
        <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div class="mt-3">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium text-gray-900" id="urlModalTitle">URL Details</h3>
                    <button onclick="closeURLModal()" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                </div>
                <div class="mt-2">
                    <pre id="modalURL" class="bg-gray-100 p-4 rounded text-sm overflow-x-auto whitespace-pre-wrap"></pre>
                </div>
                <div class="mt-4 flex justify-end">
                    <button onclick="closeURLModal()" class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
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
                document.getElementById('payloadModalTitle').textContent = 'Payload - ' + vulnerabilityType;
                document.getElementById('payloadModal').classList.remove('hidden');
            }
        }

        function closePayloadModal() {
            document.getElementById('payloadModal').classList.add('hidden');
        }

        function showEvidenceModal(evidence, vulnerabilityType) {
            if (evidence && vulnerabilityType) {
                document.getElementById('modalEvidence').textContent = evidence;
                document.getElementById('modalTitle').textContent = 'Evidence - ' + vulnerabilityType;
                document.getElementById('evidenceModal').classList.remove('hidden');
            }
        }

        function closeEvidenceModal() {
            document.getElementById('evidenceModal').classList.add('hidden');
        }

        function showRequestModal(requestData, vulnerabilityType) {
            if (requestData && vulnerabilityType) {
                document.getElementById('modalRequest').textContent = requestData;
                document.getElementById('requestModalTitle').textContent = 'Request - ' + vulnerabilityType;
                document.getElementById('requestModal').classList.remove('hidden');
            }
        }

        function closeRequestModal() {
            document.getElementById('requestModal').classList.add('hidden');
        }

        function showResponseModal(responseData, vulnerabilityType) {
            if (responseData && vulnerabilityType) {
                document.getElementById('modalResponse').textContent = responseData;
                document.getElementById('responseModalTitle').textContent = 'Response - ' + vulnerabilityType;
                document.getElementById('responseModal').classList.remove('hidden');
            }
        }

        function closeResponseModal() {
            document.getElementById('responseModal').classList.add('hidden');
        }

        function showURLModal(url, vulnerabilityType) {
            console.log('showURLModal called with:', { url, vulnerabilityType });
            
            // Check if elements exist
            const modalElement = document.getElementById('urlModal');
            const modalURLElement = document.getElementById('modalURL');
            const modalTitleElement = document.getElementById('urlModalTitle');
            
            console.log('Modal elements:', { 
                modalElement: !!modalElement, 
                modalURLElement: !!modalURLElement, 
                modalTitleElement: !!modalTitleElement 
            });
            
            if (url && vulnerabilityType && modalElement && modalURLElement && modalTitleElement) {
                console.log('Setting modal content...');
                modalURLElement.textContent = url;
                modalTitleElement.textContent = 'URL - ' + vulnerabilityType;
                modalElement.classList.remove('hidden');
                console.log('URL modal should be visible now');
            } else {
                console.log('Missing data or elements:', { 
                    url: !!url, 
                    vulnerabilityType: !!vulnerabilityType,
                    modalElement: !!modalElement,
                    modalURLElement: !!modalURLElement,
                    modalTitleElement: !!modalTitleElement
                });
            }
        }

        function closeURLModal() {
            document.getElementById('urlModal').classList.add('hidden');
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

        document.getElementById('urlModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeURLModal();
            }
        });

        // Close modals with Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closePayloadModal();
                closeEvidenceModal();
                closeRequestModal();
                closeResponseModal();
                closeURLModal();
            }
        });

        // Category filtering functionality
        document.addEventListener('DOMContentLoaded', function() {
            const categoryFilters = document.querySelectorAll('.category-filter');
            const categorySections = document.querySelectorAll('.category-section');
            const filterAllCheckbox = document.getElementById('filter-all');

            // Function to update visibility based on selected filters
            function updateCategoryVisibility() {
                const selectedCategories = [];
                
                // Get selected categories
                categoryFilters.forEach(filter => {
                    if (filter.checked && filter.id !== 'filter-all') {
                        selectedCategories.push(filter.dataset.category);
                    }
                });

                // Show/hide sections based on selection
                categorySections.forEach(section => {
                    const category = section.dataset.category;
                    if (filterAllCheckbox.checked || selectedCategories.includes(category)) {
                        section.style.display = 'block';
                    } else {
                        section.style.display = 'none';
                    }
                });
            }

            // Handle "All Categories" checkbox
            filterAllCheckbox.addEventListener('change', function() {
                if (this.checked) {
                    // Uncheck all other checkboxes
                    categoryFilters.forEach(filter => {
                        if (filter.id !== 'filter-all') {
                            filter.checked = false;
                        }
                    });
                }
                updateCategoryVisibility();
            });

            // Handle individual category checkboxes
            categoryFilters.forEach(filter => {
                if (filter.id !== 'filter-all') {
                    filter.addEventListener('change', function() {
                        if (this.checked) {
                            // Uncheck "All Categories"
                            filterAllCheckbox.checked = false;
                        }
                        updateCategoryVisibility();
                    });
                }
            });

            // Initialize visibility
            updateCategoryVisibility();
        });
    </script>
</body>
</html>`

	// Group findings by OWASP category for table analysis
	categoryGroups := r.groupFindingsByOWASPCategory(findings)

	data := struct {
		Generated       string
		TotalFindings   int
		TotalRequests   int
		ScanDuration    string
		OWASPCategories []OWASPCategoryData
		Findings        []findingData
	}{
		Generated:       time.Now().Format(time.RFC3339),
		TotalFindings:   len(findings),
		TotalRequests:   totalRequests,
		ScanDuration:    formatDuration(scanDuration),
		OWASPCategories: categoryGroups,
		Findings:        r.convertToFindingData(findings),
	}

	// Create template with custom functions
	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
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
		"formatTimestamp": func(t time.Time) string {
			return t.Format("02/01/2006 15:04:05")
		},
		"replace": func(old, new, s string) string {
			return strings.ReplaceAll(s, old, new)
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
	Requests    bool
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

// calculateTotalRequests calculates the total number of requests from findings
// This function is deprecated - use the totalRequests parameter from AttackResult instead
func (r *Reporter) calculateTotalRequests(findings []common.Finding) int {
	// For now, we'll estimate based on findings
	// In a real implementation, this would come from the scan engine
	if len(findings) == 0 {
		return 1517 // Default value when no findings
	}

	// Estimate based on findings and typical scan patterns
	// This is a rough estimate - in practice, this should come from the scan engine
	return 1517
}

// formatDuration formats duration in a human-readable format
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.0fms", float64(d.Nanoseconds())/1000000.0)
	}

	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}

	if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", hours, minutes)
}

// calculateScanDuration calculates the scan duration from findings
// This function is deprecated - use the scanDuration parameter from AttackResult instead
func (r *Reporter) calculateScanDuration(findings []common.Finding) string {
	// For now, we'll use a default value
	// In a real implementation, this would come from the scan engine
	return "4m0s"
}

// generateJSONReport generates a JSON report
func (r *Reporter) generateJSONReport(findings []common.Finding, config *common.ReportConfig) error {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	report := struct {
		Generated     string           `json:"generated"`
		TotalFindings int              `json:"total_findings"`
		Findings      []common.Finding `json:"findings"`
	}{
		Generated:     time.Now().Format(time.RFC3339),
		TotalFindings: len(findings),
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
	Method            string
	ResponseStatus    int
	ResponseSize      int64
	ResponseTime      time.Duration
	Blocked           bool
	RateLimited       bool
	URL               string
	URLPattern        string
	Payload           string
	Evidence          string
	RequestData       string
	ResponseData      string
	RequestRaw        string
	ResponseRaw       string
	Timestamp         time.Time
}

// groupFindingsForAnalysis groups findings for detailed vulnerability analysis
func (r *Reporter) groupFindingsForAnalysis(findings []common.Finding) []AnalysisGroup {
	var groups []AnalysisGroup

	for _, finding := range findings {
		// Extract URL pattern (simplify URL for analysis)
		urlPattern := r.extractURLPattern(finding.URL)

		// Keep payload full length (no truncation)
		payload := finding.Payload

		// Keep evidence full length (no truncation)
		evidence := finding.Evidence

		// Create request data for modal
		requestData := r.createRequestData(finding)
		responseData := r.createResponseData(finding)

		groups = append(groups, AnalysisGroup{
			VulnerabilityType: finding.Type,
			Category:          string(finding.Category),
			Method:            finding.Method,
			ResponseStatus:    finding.ResponseStatus,
			ResponseSize:      finding.ResponseSize,
			ResponseTime:      finding.ResponseTime,
			Blocked:           finding.Blocked,
			RateLimited:       finding.RateLimited,
			URL:               finding.URL,
			URLPattern:        urlPattern,
			Payload:           payload,
			Evidence:          evidence,
			RequestData:       requestData,
			ResponseData:      responseData,
			RequestRaw:        finding.RequestRaw,
			ResponseRaw:       finding.ResponseRaw,
			Timestamp:         finding.Timestamp,
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

// findingData represents finding data for HTML template
type findingData struct {
	Title             string
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
	RequestRaw        string
	ResponseRaw       string
}

// convertToFindingData converts findings to template data
func (r *Reporter) convertToFindingData(findings []common.Finding) []findingData {
	var data []findingData
	for _, finding := range findings {
		requestData := r.createRequestDataFromFinding(finding)
		responseData := r.createResponseDataFromFinding(finding)

		data = append(data, findingData{
			Title:             finding.Title,
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
			RequestRaw:        finding.RequestRaw,
			ResponseRaw:       finding.ResponseRaw,
		})
	}

	// Sort by category
	sort.Slice(data, func(i, j int) bool {
		return data[i].Category < data[j].Category
	})

	return data
}

// createRequestDataFromFinding creates request data from finding
func (r *Reporter) createRequestDataFromFinding(finding common.Finding) string {
	// Try to get the actual raw request from the store
	// For now, we'll build it from the finding data
	var requestData strings.Builder

	// Parse URL to get path and query
	parsedURL, err := url.Parse(finding.URL)
	if err != nil {
		return "Invalid URL"
	}

	// Build request line
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	requestData.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", finding.Method, path))

	// Add headers
	if host := parsedURL.Host; host != "" {
		requestData.WriteString(fmt.Sprintf("Host: %s\n", host))
	}
	requestData.WriteString("User-Agent: OWASPAttackSimulator/1.0\n")
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
	// Create a map of request types
	requestTypes := make(map[string]bool)
	blockedAttackTypes := make(map[string]bool)
	rateLimitedAttackTypes := make(map[string]bool)

	for _, finding := range findings {
		requestTypes[finding.Type] = true
		if finding.Blocked {
			blockedAttackTypes[finding.Type] = true
		}
		if finding.RateLimited {
			rateLimitedAttackTypes[finding.Type] = true
		}
	}

	// Define all attack types with their categories
	allAttackTypes := []struct {
		AttackType string
		Category   string
	}{
		// A01: Broken Access Control
		{string(common.AttackBrokenAccessControl), "A01: Broken Access Control"},
		{string(common.AttackIDOR), "A01: Broken Access Control"},
		{string(common.AttackPrivilegeEscalation), "A01: Broken Access Control"},
		{string(common.AttackJWTManipulation), "A01: Broken Access Control"},

		// A02: Cryptographic Failures
		{string(common.AttackWeakCrypto), "A02: Cryptographic Failures"},
		{string(common.AttackWeakHashing), "A02: Cryptographic Failures"},
		{string(common.AttackInsecureTransport), "A02: Cryptographic Failures"},

		// A03: Injection
		{string(common.AttackXSS), "A03: Injection"},
		{string(common.AttackSQLi), "A03: Injection"},
		{string(common.AttackCommandInj), "A03: Injection"},
		{string(common.AttackLDAPInjection), "A03: Injection"},
		{string(common.AttackNoSQLInjection), "A03: Injection"},
		{string(common.AttackHeaderInjection), "A03: Injection"},
		{string(common.AttackTemplateInjection), "A03: Injection"},

		// A04: Insecure Design
		{string(common.AttackBusinessLogicFlaw), "A04: Insecure Design"},
		{string(common.AttackRaceCondition), "A04: Insecure Design"},

		// A05: Security Misconfiguration
		{string(common.AttackDefaultCredentials), "A05: Security Misconfiguration"},
		{string(common.AttackDebugMode), "A05: Security Misconfiguration"},
		{string(common.AttackVerboseErrors), "A05: Security Misconfiguration"},
		{string(common.AttackMissingHeaders), "A05: Security Misconfiguration"},
		{string(common.AttackWeakCORS), "A05: Security Misconfiguration"},

		// A06: Vulnerable Components
		{string(common.AttackKnownVulnerability), "A06: Vulnerable Components"},
		{string(common.AttackOutdatedComponent), "A06: Vulnerable Components"},
		{string(common.AttackVersionDisclosure), "A06: Vulnerable Components"},

		// A07: Authentication Failures
		{string(common.AttackWeakAuth), "A07: Authentication Failures"},
		{string(common.AttackSessionFixation), "A07: Authentication Failures"},
		{string(common.AttackSessionTimeout), "A07: Authentication Failures"},
		{string(common.AttackWeakPassword), "A07: Authentication Failures"},
		{string(common.AttackBruteForce), "A07: Authentication Failures"},

		// A08: Software and Data Integrity Failures
		{string(common.AttackInsecureDeserialization), "A08: Software and Data Integrity Failures"},
		{string(common.AttackCodeInjection), "A08: Software and Data Integrity Failures"},
		{string(common.AttackSupplyChainAttack), "A08: Software and Data Integrity Failures"},

		// A09: Security Logging and Monitoring Failures
		{string(common.AttackLogInjection), "A09: Security Logging and Monitoring Failures"},
		{string(common.AttackLogBypass), "A09: Security Logging and Monitoring Failures"},
		{string(common.AttackAuditTrailTampering), "A09: Security Logging and Monitoring Failures"},

		// A10: Server-Side Request Forgery
		{string(common.AttackSSRF), "A10: Server-Side Request Forgery"},
		{string(common.AttackXXE), "A10: Server-Side Request Forgery"},
		{string(common.AttackOpenRedirect), "A10: Server-Side Request Forgery"},
	}

	var result []AllAttackTypeData
	for _, attackType := range allAttackTypes {
		requests := requestTypes[attackType.AttackType]
		blocked := blockedAttackTypes[attackType.AttackType]
		rateLimited := rateLimitedAttackTypes[attackType.AttackType]

		result = append(result, AllAttackTypeData{
			AttackType:  attackType.AttackType,
			Category:    attackType.Category,
			Requests:    requests,
			Blocked:     blocked,
			RateLimited: rateLimited,
		})
	}

	return result
}
