# OWASPAttackSimulator Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Prerequisites

- Go 1.23+
- Node.js 18+
- Docker (optional)

### Option 1: Quick Start with CLI Only

```bash
# 1. Clone and build
git clone https://github.com/owaspattacksimulator/owaspchecker.git
cd owaspchecker
go build -o apps/cli/simulation ./apps/cli

# 2. Test the CLI
./apps/cli/simulation --help

# 3. Run a sample scenario
./apps/cli/simulation run scenario --file configs/scenarios/login_attack.yaml
```

### Option 2: Full Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/owaspattacksimulator/owaspchecker.git
cd owaspchecker

# 2. Install dependencies
make -f scripts/Makefile install-deps

# 3. Install protobuf tools (if needed)
make -f scripts/Makefile install-protobuf

# 4. Build the project
make -f scripts/Makefile build

# 5. Start development environment
make -f scripts/Makefile dev
```

### Option 3: Docker Setup

```bash
# 1. Clone the repository
git clone https://github.com/owaspattacksimulator/owaspchecker.git
cd owaspchecker

# 2. Start with Docker Compose
docker-compose up -d

# 3. Check services
docker-compose ps
```

## 📋 Basic Usage

### 1. Start a Session

```bash
# Connect to a target
simulation session connect --target https://target.app

# Check session status
simulation session status
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
  --concurrency 8
```

### 3. Import/Export Data

```bash
# Import HAR file
simulation import har --file session.har

# Export security report
simulation export report --format md --out security_report.md

# Export HAR file
simulation export har --file session.har --filter tag=attack
```

### 4. Database Management

```bash
# Show database statistics
simulation db stats

# Optimize database
simulation db vacuum
```

## 🔧 Configuration

### Environment Variables

```bash
export SIMULATION_CONFIG=/path/to/config.yaml
export SIMULATION_DB_PATH=/path/to/database.db
export SIMULATION_LOG_LEVEL=debug
```

### Configuration File

Edit `configs/defaults.yaml` to customize:

- HTTP timeouts and rate limits
- Security check settings
- Database configuration
- Plugin settings

## 📝 Sample Scenarios

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

### Infinite Attack Loop

```yaml
version: "1"
name: "Infinite Attack Loop"
steps:
  - id: loop_forever
    type: control:while
    inputs:
      condition: "true"
    children:
      - id: attack_cycle
        type: net:attack
        inputs:
          target:
            url: "https://target.app/api/data"
          mutate:
            payload_sets: "[xss.reflected, sqli.time]"
        effects:
          sleep_after: "30s"
```

## 🐛 Troubleshooting

### Common Issues

1. **Protobuf tools missing**
   ```bash
   make -f scripts/Makefile install-protobuf
   ```

2. **Docker Compose errors**
   ```bash
   docker-compose down
   docker-compose up -d
   ```

3. **Permission denied**
   ```bash
   chmod +x scripts/install-protobuf.sh
   ```

4. **Go module issues**
   ```bash
   go mod tidy
   go mod download
   ```

### Getting Help

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/owaspattacksimulator/owaspchecker/issues)
- **Discussions**: [GitHub Discussions](https://github.com/owaspattacksimulator/owaspchecker/discussions)

## 🔒 Security Notice

⚠️ **Important**: This tool is for authorized security testing only. Always obtain proper authorization before testing any system.

- Only test applications you own or have explicit permission to test
- Be aware of local laws and regulations
- Use in controlled environments only
- Some payloads may trigger security systems

## 📚 Next Steps

1. **Read the Documentation**: [docs/SCENARIO_DSL.md](docs/SCENARIO_DSL.md)
2. **Explore Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
3. **Create Custom Scenarios**: Use the sample scenarios as templates
4. **Develop Plugins**: Extend functionality with custom plugins
5. **Join the Community**: Contribute to the project

---

**Happy Security Testing!** 🎯
