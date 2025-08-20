# OWASPChecker

A comprehensive web application security scanner focusing on OWASP Top 10 vulnerabilities, written in Go.

## Features

- **Web Crawling**: Automatically discover links, forms, and endpoints
- **Request Loading**: Import requests from HAR files or JSON
- **Payload Injection**: Test with various attack payloads (XSS, SQLi, XXE, SSRF, etc.)
- **Vulnerability Detection**: Automated detection of security issues
- **Comprehensive Reporting**: Generate reports in Markdown, HTML, or JSON formats
- **Concurrent Testing**: Configurable concurrency for efficient scanning
- **SQLite Storage**: Persistent storage of requests, responses, and findings
- **Progress Tracking**: Real-time progress bars and status updates
- **Colorful Output**: Rich terminal interface with emojis and colors
- **Smart CLI**: Single command handles crawl, attack, and report generation

## Installation

### Prerequisites

- Go 1.21 or later
- SQLite3

### Build

```bash
git clone <repository-url>
cd OWASPChecker
go mod tidy
go build -o owaspchecker cmd/owaspchecker/main.go
```

## Usage

### Basic Commands

```bash
# Crawl and attack a website
./owaspchecker https://example.com

# Attack requests from a HAR file
./owaspchecker requests.har

# Attack requests from a JSON file
./owaspchecker requests.json
```

### Command Options

- `--depth, -d`: Maximum crawl depth (only for URL) (default: 3)
- `--concurrency, -c`: Number of concurrent requests (default: 10)
- `--format, -f`: Report format: markdown, html, json (default: markdown)
- `--crawl-only`: Only crawl, don't attack
- `--attack-only`: Only attack, don't crawl

## Supported Attack Types

### Cross-Site Scripting (XSS)
- Basic script injection
- Event handler injection
- JavaScript protocol injection
- SVG onload injection
- Quote breaking

### SQL Injection
- Boolean-based injection
- Time-based injection
- Union-based injection
- Error-based detection

### XML External Entity (XXE)
- File read attempts
- SSRF through XXE
- PHP filter injection

### Server-Side Request Forgery (SSRF)
- Localhost access
- Cloud metadata endpoints
- Internal service discovery

### Command Injection
- File system access
- Command execution
- Backtick injection
- Dollar-parens injection

### Header Injection
- X-Forwarded-For spoofing
- Host header manipulation
- Custom header injection

## Workflow

OWASPChecker automatically performs the complete security testing workflow:

1. **Discovery**: Crawl the website to discover endpoints (if URL provided)
2. **Testing**: Attack discovered endpoints with various payloads
3. **Analysis**: Generate comprehensive security reports

## Example Workflow

```bash
# Complete security scan of a website
./owaspchecker https://vulnerable-webapp.com --depth 2 --concurrency 15

# Attack requests from a file
./owaspchecker requests.har --concurrency 10

# Only crawl without attacking
./owaspchecker https://example.com --crawl-only

# Generate HTML report
./owaspchecker requests.har --format html

# Quick scan with default settings
./owaspchecker https://example.com
```

## Output Files

- `owaspchecker.db`: SQLite database containing all requests, responses, and findings
- `owaspchecker_report.md`: Markdown security report
- `owaspchecker_report.html`: HTML security report with styling
- `owaspchecker_report.json`: JSON security report

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only. Always ensure you have proper authorization before testing any application.

- Only test applications you own or have explicit permission to test
- Be aware of local laws and regulations regarding security testing
- Some payloads may trigger security systems or cause application instability
- Use in controlled environments only

## Project Structure

```
OWASPChecker/
├── cmd/
│   └── owaspchecker/        # Main CLI entry
├── internal/
│   ├── cli/                 # CLI commands
│   ├── crawl/               # Link discovery
│   ├── httpx/               # HTTP client wrapper
│   ├── mutate/              # Payload generator
│   ├── attack/              # Attack engine
│   ├── checks/              # OWASP checks
│   ├── store/               # Storage (SQLite)
│   ├── report/              # Reporting
│   ├── har/                 # HAR/JSON import/export
│   └── common/              # Shared types
├── go.mod                   # Go module
└── README.md               # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any application.
