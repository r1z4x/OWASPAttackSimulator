# OWASPChecker

[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org)
[![Node Version](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

A comprehensive scenario-based security testing framework with infinite-step attack infrastructure, featuring GUI/CLI support, gRPC communication, and comprehensive OWASP vulnerability detection.

## 🚀 Features

- **Infinite-Step Scenarios**: Declarative YAML-based scenario DSL with loops, conditions, and variables
- **Dual Interface**: CLI (Go + Cobra) and GUI (TypeScript + Playwright) support
- **Comprehensive Testing**: XSS, SQLi, SSRF, XXE, CSRF, CORS, AuthZ, and more
- **Real-time Monitoring**: Live event streaming and progress tracking
- **Session Management**: Browser session synchronization and CSRF token handling
- **Plugin Architecture**: Extensible Go and TypeScript plugin system
- **Multiple Outputs**: HAR, JSON, Markdown, and HTML report formats
- **Docker Support**: Containerized deployment with Docker Compose

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Scenario DSL](#scenario-dsl)
- [CLI Commands](#cli-commands)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## 🛠 Installation

### Prerequisites

- Go 1.23+
- Node.js 18+
- SQLite 3
- Docker (optional)

### From Source

```bash
# Clone the repository
git clone https://github.com/owaspchecker/owaspchecker.git
cd owaspchecker

# Install dependencies
make install-deps

# Build the project
make build

# Run tests
make test
```

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or run all-in-one container
docker-compose --profile all-in-one up -d
```

## 🚀 Quick Start

### 1. Start a Session

```bash
# Connect to target with CLI
owaspchecker session connect --target https://target.app

# Or start GUI runner
cd apps/gui-runner && pnpm dev
```

### 2. Run a Scenario

```bash
# Execute a scenario file
owaspchecker run scenario --file configs/scenarios/login_attack.yaml

# Run with custom variables
owaspchecker run scenario \
  --file configs/scenarios/login_attack.yaml \
  --vars base_url=https://target.app \
  --vars username=admin \
  --concurrency 8 \
  --timeout 30s
```

### 3. Export Results

```bash
# Export findings as Markdown
owaspchecker export report --format md --out security_report.md

# Export HAR file
owaspchecker export har --file session.har --filter tag=attack
```

### 4. Import Data

```bash
# Import HAR file
owaspchecker import har --file session.har

# Import JSON data
owaspchecker import json --file endpoints.json
```

## 🏗 Architecture

OWASPChecker follows a microservices architecture with the following components:

- **CLI Application** (`apps/cli`): Go-based command-line interface
- **GUI Runner** (`apps/gui-runner`): TypeScript + Playwright browser automation
- **gRPC Broker** (`pkg/broker`): Communication layer with Protocol Buffers
- **Core Engine** (`pkg/engine`): Attack job queue and worker management
- **Scenario Runner** (`pkg/scenario`): YAML parser and state machine
- **Security Checks** (`pkg/checks`): OWASP vulnerability detection
- **Data Store** (`pkg/store`): SQLite persistence layer

For detailed architecture information, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 📝 Scenario DSL

OWASPChecker uses a declarative YAML-based Domain Specific Language for defining security testing scenarios.

### Basic Example

```yaml
version: "1"
name: "Login Attack Scenario"
vars:
  base_url: "https://target.app"
  username: "{{ env:APP_USER }}"

steps:
  - id: open_login
    type: browser:navigate
    inputs:
      url: "{{ vars.base_url }}/login"
      wait: "networkidle"
    timeout: 30s

  - id: attack_api
    type: net:attack
    inputs:
      target:
        url: "{{ vars.base_url }}/api/profile"
      mutate:
        methods: "[GET, POST]"
        payload_sets: "[xss.reflected, sqli.time]"
      checks:
        enabled: "[xss, sqli]"
    timeout: 60s
```

For complete DSL documentation, see [SCENARIO_DSL.md](docs/SCENARIO_DSL.md).

## 💻 CLI Commands

### Session Management

```bash
# Connect to target
owaspchecker session connect --target <url> [--from-har <file>] [--headless]

# Check session status
owaspchecker session status

# Close session
owaspchecker session close
```

### Scenario Execution

```bash
# Run scenario file
owaspchecker run scenario --file <scenario.yaml> [--vars key=val...]

# Execute single step
owaspchecker run step --name <step-id> [--repeat N]
```

### Data Import/Export

```bash
# Import HAR file
owaspchecker import har --file <file.har>

# Import JSON data
owaspchecker import json --file <file.json>

# Export HAR file
owaspchecker export har --file <out.har> [--filter tag=attack]

# Export security report
owaspchecker export report --format <md|html|json> --out <report.md>
```

### Database Management

```bash
# Show database statistics
owaspchecker db stats

# Optimize database
owaspchecker db vacuum
```

### Plugin Management

```bash
# List available plugins
owaspchecker plugin list

# Build plugin
owaspchecker plugin build --src ./plugins/myplugin

# Enable/disable plugin
owaspchecker plugin enable --name myplugin
owaspchecker plugin disable --name myplugin
```

## ⚙️ Configuration

Configuration is managed through YAML files with environment variable overrides.

### Default Configuration

```yaml
# configs/defaults.yaml
broker:
  addr: "localhost:50051"

http:
  timeouts:
    connect: "10s"
    read: "30s"
  rate_limit:
    requests_per_second: 10

engine:
  concurrency:
    default: 8
    max: 32

checks:
  enabled:
    - "xss"
    - "sqli"
    - "ssrf"
    - "xxe"
```

### Environment Variables

```bash
export OWASPCHECKER_CONFIG=/path/to/config.yaml
export OWASPCHECKER_DB_PATH=/path/to/database.db
export OWASPCHECKER_LOG_LEVEL=debug
```

## 🔌 Plugin Development

### Go Plugin Example

```go
package main

import (
    "github.com/owaspchecker/pkg/plugins"
    "github.com/owaspchecker/pkg/common"
)

type MyPlugin struct{}

func (p *MyPlugin) Init(config map[string]interface{}) error {
    // Initialize plugin
    return nil
}

func (p *MyPlugin) Steps() []plugins.StepDefinition {
    return []plugins.StepDefinition{
        {
            Name: "custom_attack",
            Type: "plugin:custom",
            Handler: p.customAttack,
        },
    }
}

func (p *MyPlugin) customAttack(ctx context.Context, step *common.Step) error {
    // Implement custom attack logic
    return nil
}

func main() {
    plugins.Register(&MyPlugin{})
}
```

### TypeScript Plugin Example

```typescript
interface Plugin {
    name: string;
    actions: Record<string, ActionFunction>;
}

const myPlugin: Plugin = {
    name: 'custom-plugin',
    actions: {
        'custom-action': async (params: any) => {
            // Implement custom action
            console.log('Custom action executed:', params);
        }
    }
};

export default myPlugin;
```

## 🧪 Testing

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests
make test-integration

# Run GUI tests
make test-gui

# Run end-to-end tests
make test-e2e
```

## 📊 Monitoring

### Metrics

OWASPChecker provides comprehensive metrics:

- Request/response counts
- Attack success rates
- Performance latencies
- Error rates and types

### Health Checks

```bash
# Check service health
curl http://localhost:3000/health

# Check database connectivity
owaspchecker db stats
```

## 🐳 Docker Deployment

### Development

```bash
# Start development environment
docker-compose up -d

# View logs
docker-compose logs -f
```

### Production

```bash
# Build production images
make docker-build

# Deploy with monitoring
docker-compose --profile monitoring up -d
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone
git clone https://github.com/your-username/owaspchecker.git
cd owaspchecker

# Install dependencies
make install-deps

# Start development environment
make dev

# Run tests
make test
```

### Code Style

```bash
# Format code
make fmt

# Run linters
make lint

# Fix lint issues
make lint-fix
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security guidelines
- [Playwright](https://playwright.dev/) for browser automation
- [gRPC](https://grpc.io/) for communication layer
- [Cobra](https://github.com/spf13/cobra) for CLI framework

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/owaspchecker/owaspchecker/issues)
- **Discussions**: [GitHub Discussions](https://github.com/owaspchecker/owaspchecker/discussions)
- **Security**: [Security Policy](SECURITY.md)

---

**⚠️ Legal Notice**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system. The authors are not responsible for any misuse of this software.
