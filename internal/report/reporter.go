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
	case "markdown":
		return r.generateMarkdownReport(findings, config)
	case "html":
		return r.generateHTMLReport(findings, config)
	case "json":
		return r.generateJSONReport(findings, config)
	default:
		return fmt.Errorf("unsupported output format: %s", config.OutputFormat)
	}
}

// generateMarkdownReport generates a markdown report
func (r *Reporter) generateMarkdownReport(findings []common.Finding, config *common.ReportConfig) error {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# OWASPChecker Security Report\n\n")
	fmt.Fprintf(file, "Generated: %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(file, "Total Findings: %d\n\n", len(findings))

	// Summary
	fmt.Fprintf(file, "## Summary\n\n")
	severityCounts := r.countBySeverity(findings)
	for severity, count := range severityCounts {
		fmt.Fprintf(file, "- **%s**: %d\n", severity, count)
	}
	fmt.Fprintf(file, "\n")

	// Group by severity if requested
	if config.GroupBySeverity {
		r.writeMarkdownBySeverity(file, findings, config)
	} else {
		r.writeMarkdownByType(file, findings, config)
	}

	return nil
}

// generateHTMLReport generates an HTML report
func (r *Reporter) generateHTMLReport(findings []common.Finding, config *common.ReportConfig) error {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// HTML template
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <title>OWASPChecker Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #dc3545; background-color: #f8d7da; }
        .high { border-left: 5px solid #fd7e14; background-color: #fff3cd; }
        .medium { border-left: 5px solid #ffc107; background-color: #fff3cd; }
        .low { border-left: 5px solid #28a745; background-color: #d4edda; }
        .severity { font-weight: bold; }
        .evidence { background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>OWASPChecker Security Report</h1>
    <p><strong>Generated:</strong> {{.Generated}}</p>
    <p><strong>Total Findings:</strong> {{.TotalFindings}}</p>
    
    <h2>Summary</h2>
    <ul>
    {{range $severity, $count := .SeverityCounts}}
        <li><strong>{{$severity}}:</strong> {{$count}}</li>
    {{end}}
    </ul>
    
    <h2>Findings</h2>
    {{range .Findings}}
    <div class="finding {{.SeverityClass}}">
        <h3>{{.Title}}</h3>
        <p><strong>Severity:</strong> <span class="severity">{{.Severity}}</span></p>
        <p><strong>Category:</strong> {{.Category}}</p>
        <p><strong>URL:</strong> {{.URL}}</p>
        <p><strong>Method:</strong> {{.Method}}</p>
        <p><strong>Description:</strong> {{.Description}}</p>
        {{if .Evidence}}
        <p><strong>Evidence:</strong></p>
        <div class="evidence">{{.Evidence}}</div>
        {{end}}
        {{if .Payload}}
        <p><strong>Payload:</strong> <code>{{.Payload}}</code></p>
        {{end}}
        <p><strong>Timestamp:</strong> {{.Timestamp}}</p>
    </div>
    {{end}}
</body>
</html>`

	// Prepare data for template
	data := struct {
		Generated      string
		TotalFindings  int
		SeverityCounts map[common.Severity]int
		Findings       []findingData
	}{
		Generated:      time.Now().Format(time.RFC3339),
		TotalFindings:  len(findings),
		SeverityCounts: r.countBySeverity(findings),
		Findings:       r.convertToFindingData(findings),
	}

	// Execute template
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl.Execute(file, data)
}

// generateJSONReport generates a JSON report
func (r *Reporter) generateJSONReport(findings []common.Finding, config *common.ReportConfig) error {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	report := struct {
		Generated     string                    `json:"generated"`
		TotalFindings int                       `json:"total_findings"`
		Summary       map[common.Severity]int   `json:"summary"`
		Findings      []common.Finding          `json:"findings"`
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

// writeMarkdownBySeverity writes findings grouped by severity
func (r *Reporter) writeMarkdownBySeverity(file *os.File, findings []common.Finding, config *common.ReportConfig) {
	severities := []common.Severity{common.SeverityCritical, common.SeverityHigh, common.SeverityMedium, common.SeverityLow}

	for _, severity := range severities {
		severityFindings := r.filterBySeverity(findings, severity)
		if len(severityFindings) == 0 {
			continue
		}

		fmt.Fprintf(file, "## %s Severity (%d)\n\n", strings.Title(string(severity)), len(severityFindings))

		for _, finding := range severityFindings {
			r.writeMarkdownFinding(file, finding, config)
		}
		fmt.Fprintf(file, "\n")
	}
}

// writeMarkdownByType writes findings grouped by type
func (r *Reporter) writeMarkdownByType(file *os.File, findings []common.Finding, config *common.ReportConfig) {
	fmt.Fprintf(file, "## Findings\n\n")

	for _, finding := range findings {
		r.writeMarkdownFinding(file, finding, config)
	}
}

// writeMarkdownFinding writes a single finding in markdown
func (r *Reporter) writeMarkdownFinding(file *os.File, finding common.Finding, config *common.ReportConfig) {
	fmt.Fprintf(file, "### %s\n\n", finding.Title)
	fmt.Fprintf(file, "- **Severity**: %s\n", finding.Severity)
	fmt.Fprintf(file, "- **Category**: %s\n", finding.Category)
	fmt.Fprintf(file, "- **URL**: `%s`\n", finding.URL)
	fmt.Fprintf(file, "- **Method**: %s\n", finding.Method)
	fmt.Fprintf(file, "- **Description**: %s\n", finding.Description)

	if config.IncludeEvidence && finding.Evidence != "" {
		fmt.Fprintf(file, "- **Evidence**:\n```\n%s\n```\n", finding.Evidence)
	}

	if finding.Payload != "" {
		fmt.Fprintf(file, "- **Payload**: `%s`\n", finding.Payload)
	}

	fmt.Fprintf(file, "- **Timestamp**: %s\n\n", finding.Timestamp.Format(time.RFC3339))
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
	Title       string
	Severity    common.Severity
	SeverityClass string
	Category    string
	URL         string
	Method      string
	Description string
	Evidence    string
	Payload     string
	Timestamp   string
}

// convertToFindingData converts findings to template data
func (r *Reporter) convertToFindingData(findings []common.Finding) []findingData {
	var data []findingData
	for _, finding := range findings {
		data = append(data, findingData{
			Title:        finding.Title,
			Severity:     finding.Severity,
			SeverityClass: strings.ToLower(string(finding.Severity)),
			Category:     finding.Category,
			URL:          finding.URL,
			Method:       finding.Method,
			Description:  finding.Description,
			Evidence:     finding.Evidence,
			Payload:      finding.Payload,
			Timestamp:    finding.Timestamp.Format(time.RFC3339),
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
