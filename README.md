# OWASPAttackSimulator

[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://golang.org)
[![Node Version](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

A comprehensive security testing framework with attack infrastructure, featuring CLI support and OWASP vulnerability detection.

## Features

- **Direct Attack Testing**: Run attacks against target URLs with configurable payloads and variations
- **Scenario-based Testing**: Execute YAML-based scenarios with automatic session management
- **Comprehensive Testing**: XSS, SQLi, SSRF, XXE, CSRF, CORS, AuthZ, and more
- **Multiple Outputs**: HTML, JSON, and text report formats
- **Docker Support**: Containerized deployment with Docker Compose

## Quick Installation

### Prerequisites
- Go 1.23+
- Node.js 18+
- SQLite 3

### From Source
```bash
git clone git@github.com:r1z4x/OWASPAttackSimulator.git
cd OWASPAttackSimulator
make install-deps
make build
```

### Using Docker
```bash
docker-compose up -d
```

## Quick Start

```bash
# Run a direct attack
simulation attack --target https://target.app

# Run a scenario
simulation scenario --file configs/scenarios/login_attack.yaml

# Generate a report
simulation report --format html --output security_report.html
```

## Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in 5 minutes
- **[Scenario DSL](docs/SCENARIO_DSL.md)** - Learn the scenario language
- **[Architecture](docs/ARCHITECTURE.md)** - System design and components
- **[Variation Sets](docs/VARIATION_SETS.md)** - Configure attack variations

## CLI Commands

```bash
# Direct attack
simulation attack --target <url> [--payload-set <set>] [--variation-set <sets>]

# Scenario execution
simulation scenario --file <scenario.yaml> [--workers <n>] [--timeout <duration>]

# Report generation
simulation report --format <html|json|text> --output <file>

# gRPC server
simulation server [--port <port>]
```

## Configuration

Configuration is managed through `configs/defaults.yaml` with environment variable overrides:

```bash
export SIMULATION_CONFIG=/path/to/config.yaml
export SIMULATION_DB_PATH=/path/to/database.db
export SIMULATION_LOG_LEVEL=debug
```

## Testing

```bash
make test
make test-unit
make test-integration
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/r1z4x/OWASPAttackSimulator/issues)

---

**⚠️ Legal Notice**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system. The authors are not responsible for any misuse of this software.
