# OWASPAttackSimulator

[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org)
[![Node Version](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

A comprehensive scenario-based security testing framework with infinite-step attack infrastructure, featuring GUI/CLI support, gRPC communication, and comprehensive OWASP vulnerability detection.

## Features

- **Infinite-Step Scenarios**: Declarative YAML-based scenario DSL with loops, conditions, and variables
- **Dual Interface**: CLI (Go + Cobra) and GUI (TypeScript + Playwright) support
- **Comprehensive Testing**: XSS, SQLi, SSRF, XXE, CSRF, CORS, AuthZ, and more
- **Real-time Monitoring**: Live event streaming and progress tracking
- **Session Management**: Browser session synchronization and CSRF token handling
- **Plugin Architecture**: Extensible Go and TypeScript plugin system
- **Multiple Outputs**: HAR, JSON, Markdown, and HTML report formats
- **Docker Support**: Containerized deployment with Docker Compose

## Installation

### Prerequisites

- Go 1.23+
- Node.js 18+
- SQLite 3
- Docker (optional)

### From Source

```bash
git clone https://github.com/owaspchecker/owaspchecker.git
cd owaspchecker
make install-deps
make build
```

### Using Docker

```bash
docker-compose up -d
```

## Quick Start

### 1. Start a Session

```bash
# Connect to target with CLI
simulation session connect --target https://target.app

# Or start GUI runner
cd apps/gui-runner && pnpm dev
```

### 2. Run a Scenario

```bash
# Execute a scenario file
simulation run scenario --file configs/scenarios/login_attack.yaml

# Run with custom variables
simulation run scenario \
  --file configs/scenarios/login_attack.yaml \
  --vars base_url=https://target.app \
  --vars username=admin \
  --concurrency 8 \
  --timeout 30s
```

### 3. Export Results

```bash
# Export findings as Markdown
simulation export report --format md --out security_report.md

# Export HAR file
simulation export har --file session.har --filter tag=attack
```

## CLI Commands

### Session Management

```bash
simulation session connect --target <url> [--from-har <file>] [--headless]
simulation session status
simulation session close
```

### Scenario Execution

```bash
simulation run scenario --file <scenario.yaml> [--vars key=val...]
simulation run step --name <step-id> [--repeat N]
```

### Data Import/Export

```bash
simulation import har --file <file.har>
simulation import json --file <file.json>
simulation export har --file <out.har> [--filter tag=attack]
simulation export report --format <md|html|json> --out <report.md>
```

### Database Management

```bash
simulation db stats
simulation db vacuum
```

## Configuration

Configuration is managed through YAML files with environment variable overrides.

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

## Architecture

- **CLI Application** (`apps/cli`): Go-based command-line interface
- **GUI Runner** (`apps/gui-runner`): TypeScript + Playwright browser automation
- **gRPC Broker** (`pkg/broker`): Communication layer with Protocol Buffers
- **Core Engine** (`pkg/engine`): Attack job queue and worker management
- **Scenario Runner** (`pkg/scenario`): YAML parser and state machine
- **Security Checks** (`pkg/checks`): OWASP vulnerability detection
- **Data Store** (`pkg/store`): SQLite persistence layer

For detailed architecture information, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Scenario DSL

OWASPAttackSimulator uses a declarative YAML-based Domain Specific Language for defining security testing scenarios.

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

## Testing

```bash
make test
make test-unit
make test-integration
make test-gui
make test-e2e
```

## Docker Deployment

```bash
# Development
docker-compose up -d

# Production
make docker-build
docker-compose --profile monitoring up -d
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/owaspchecker/owaspchecker/issues)
- **Discussions**: [GitHub Discussions](https://github.com/owaspchecker/owaspchecker/discussions)
- **Security**: [Security Policy](SECURITY.md)

---

**⚠️ Legal Notice**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system. The authors are not responsible for any misuse of this software.
