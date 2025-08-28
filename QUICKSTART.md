# OWASPAttackSimulator Quick Start Guide

## Get Started in 5 Minutes

### Prerequisites
- Go 1.23+
- Node.js 18+

### Quick Setup

```bash
# Clone and build
git clone git@github.com:r1z4x/OWASPAttackSimulator.git
cd  OWASPAttackSimulator
make install-deps
make build

# Test the CLI
./apps/cli/simulation --help
```

## Basic Usage

### 1. Run a Direct Attack

```bash
# Attack a target URL
simulation attack --target https://target.app

# Attack with specific payload set
simulation attack --target https://target.app --payload-set xss.reflected

# Attack with custom variations
simulation attack --target https://target.app --variation-set method,header
```

### 2. Run a Scenario

```bash
# Execute a scenario file
simulation scenario --file configs/scenarios/login_attack.yaml

# Run with custom settings
simulation scenario \
  --file configs/scenarios/login_attack.yaml \
  --workers 8 \
  --timeout 120s
```

### 3. Generate Reports

```bash
# Generate HTML report
simulation report --format html --output security_report.html

# Generate JSON report
simulation report --format json --output findings.json
```

## Sample Scenarios

### Basic Login Attack

```yaml
version: "1"
name: "Basic Login Attack"
vars:
  base_url: "https://target.app"
  username: "{{ env:APP_USER }}"

steps:
  - id: login
    type: browser:navigate
    inputs:
      url: "{{ vars.base_url }}/login"
      wait: "networkidle"
    timeout: 30s

  - id: attack
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

## Configuration

### Environment Variables

```bash
export SIMULATION_CONFIG=/path/to/config.yaml
export SIMULATION_DB_PATH=/path/to/database.db
export SIMULATION_LOG_LEVEL=debug
```

## Troubleshooting

### Common Issues

1. **Protobuf tools missing**
   ```bash
   make -f scripts/Makefile install-protobuf
   ```

2. **Go module issues**
   ```bash
   go mod tidy
   go mod download
   ```

## Security Notice

**Important**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system.

**Happy Security Testing!**
