# OWASPChecker Architecture

## Overview

OWASPChecker is a comprehensive security testing framework built with a microservices architecture. It consists of a Go-based core engine, TypeScript GUI runner, gRPC communication layer, and SQLite persistence layer.

## Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Client    │    │   GUI Runner    │    │   Web Browser   │
│   (Go + Cobra)  │    │ (TS + Playwright)│    │   (Playwright)  │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │      gRPC Broker          │
                    │   (Session/Step/Event)    │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │      Core Engine          │
                    │   (Go + State Machine)    │
                    └─────────────┬─────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
┌─────────┴─────────┐  ┌─────────┴─────────┐  ┌─────────┴─────────┐
│   Attack Engine   │  │  Scenario Runner  │  │   Security Checks │
│   (Queue/Workers) │  │  (YAML Parser)    │  │   (OWASP Tests)   │
└─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │      SQLite Store         │
                    │   (Requests/Findings)     │
                    └───────────────────────────┘
```

## Core Components

### 1. CLI Application (`apps/cli`)

**Technology**: Go + Cobra

**Responsibilities**:
- Command-line interface for all operations
- Session management (connect, status, close)
- Scenario execution (run, step)
- Data import/export (HAR, JSON, reports)
- Database management (vacuum, stats)
- Plugin management (build, enable, disable)

**Key Commands**:
```bash
owaspchecker session connect --target <url>
owaspchecker run scenario --file <scenario.yaml>
owaspchecker export report --format md --out report.md
```

### 2. GUI Runner (`apps/gui-runner`)

**Technology**: TypeScript + Playwright

**Responsibilities**:
- Browser automation and control
- Session context synchronization
- Network request interception
- Real-time event streaming
- Visual scenario monitoring

**Features**:
- Headless/headful browser control
- Cookie and storage synchronization
- HAR export capabilities
- Live step execution monitoring

### 3. gRPC Broker (`pkg/broker`)

**Technology**: gRPC + Protocol Buffers

**Services**:
- **SessionService**: Session lifecycle management
- **StepService**: Step execution and monitoring
- **ArtifactService**: File and data artifact management

**Protocol Buffers**:
- `broker.proto`: Core communication protocol
- `scenario.proto`: Scenario definition and execution

### 4. Core Engine (`pkg/engine`)

**Technology**: Go + State Machine

**Responsibilities**:
- Attack job queue management
- Worker pool coordination
- Rate limiting and backoff
- Circuit breaker implementation
- Metrics collection

**Features**:
- Priority-based job queuing
- Configurable concurrency control
- Exponential backoff retry
- Performance metrics tracking

### 5. Scenario Runner (`pkg/scenario`)

**Technology**: Go + YAML Parser

**Responsibilities**:
- YAML scenario parsing and validation
- State machine execution
- Variable substitution
- Control flow management
- Event generation

**State Machine**:
- Step execution lifecycle
- Pause/resume capabilities
- Error handling and recovery
- Progress tracking

### 6. Security Checks (`pkg/checks`)

**Technology**: Go + OWASP Guidelines

**Vulnerability Categories**:
- **XSS**: Reflected and DOM-based detection
- **SQLi**: Error-based and time-based detection
- **SSRF**: Internal IP and DNS log detection
- **XXE**: File inclusion and entity expansion
- **CSRF**: Token validation and state change detection
- **CORS**: Origin validation and header analysis
- **AuthZ**: IDOR and access control testing

### 7. Mutation Engine (`pkg/mutate`)

**Technology**: Go + Payload Sets

**Mutation Strategies**:
- **Method Variation**: GET, POST, PUT, DELETE, PATCH
- **Header Injection**: X-Forwarded-For, User-Agent, etc.
- **Body Mutation**: JSON, XML, Form, Multipart
- **URL Parameter Fuzzing**: Encoding, traversal, reserved chars
- **Payload Sets**: Tagged vulnerability-specific payloads

### 8. HTTP Client (`pkg/httpx`)

**Technology**: Go + Custom RoundTripper

**Features**:
- Request/response recording
- HAR export capabilities
- Retry logic with backoff
- Proxy and TLS configuration
- Timing attack support

### 9. Session Management (`pkg/session`)

**Technology**: Go + Cookie Jar

**Features**:
- Shared cookie jar (HTTP + Playwright)
- CSRF token extraction
- Header policy management
- Storage synchronization
- Secrets provider integration

### 10. Data Store (`pkg/store`)

**Technology**: SQLite + Go

**Schema**:
```sql
-- Core tables
requests(id, method, url, headers_json, body_blob, content_type, variant, ts)
responses(id, request_id, status, headers_json, body_snippet, body_hash, duration_ms, ts)
findings(id, request_id, category, title, severity, evidence, tags_json, ts)
sessions(id, cookies_json, headers_json, csrf_token, storage_json, ts)
events(id, step_id, kind, payload_json, ts)
artifacts(id, step_id, kind, path, meta_json, ts)
```

### 11. Report Generator (`pkg/report`)

**Technology**: Go + Templates

**Output Formats**:
- **Markdown**: Human-readable reports
- **HTML**: Interactive web reports
- **JSON**: Machine-readable data
- **Timeline**: Chronological event view
- **Statistics**: Severity and category summaries

## Data Flow

### 1. Session Establishment

```
CLI/GUI → gRPC Broker → Session Service → Core Engine → SQLite Store
```

### 2. Scenario Execution

```
Scenario YAML → Parser → State Machine → Step Executor → Attack Engine → Security Checks → Findings Store
```

### 3. Attack Execution

```
Attack Job → Queue → Worker → HTTP Client → Target → Response → Security Checks → Findings
```

### 4. Event Streaming

```
Step Execution → Event Bus → gRPC Stream → GUI/CLI → Real-time Updates
```

## Security Features

### 1. Dangerous Payload Protection

- XXE payloads disabled by default
- SSRF payloads require explicit enablement
- Command injection payloads guarded
- Rate limiting to prevent DoS

### 2. Scope Control

- Base URL validation
- Domain allowlist/blocklist
- Robots.txt respect (optional)
- Legal banner and audit logging

### 3. Session Security

- CSRF token extraction and validation
- Secure cookie handling
- Header sanitization
- Storage isolation

## Performance Considerations

### 1. Concurrency Control

- Configurable worker pools
- Queue size limits
- Rate limiting per target
- Circuit breaker patterns

### 2. Resource Management

- Connection pooling
- Memory-efficient request storage
- Database connection limits
- Artifact cleanup policies

### 3. Scalability

- Horizontal scaling via multiple instances
- Database sharding capabilities
- Load balancing support
- Metrics and monitoring

## Deployment Options

### 1. Single Binary

```bash
go build -o owaspchecker ./apps/cli
./owaspchecker
```

### 2. Docker Containers

```bash
# Individual services
docker-compose up cli gui

# All-in-one container
docker-compose up all-in-one
```

### 3. Kubernetes

```yaml
# Deployment manifests available
kubectl apply -f k8s/
```

## Monitoring and Observability

### 1. Metrics

- Request/response counts
- Attack success rates
- Performance latencies
- Error rates and types

### 2. Logging

- Structured JSON logging
- Configurable log levels
- Audit trail preservation
- Error tracking

### 3. Health Checks

- Service health endpoints
- Database connectivity
- gRPC service status
- Resource utilization

## Plugin Architecture

### 1. Go Plugins

```go
type Plugin interface {
    Init(config map[string]interface{}) error
    Steps() []StepDefinition
    OnEvent(event *Event) error
}
```

### 2. TypeScript Plugins

```typescript
interface Plugin {
    name: string;
    actions: Record<string, ActionFunction>;
    init?: (config: any) => Promise<void>;
}
```

### 3. Plugin Management

- Dynamic loading/unloading
- Configuration management
- Version compatibility
- Security sandboxing

## Future Enhancements

### 1. Cloud Integration

- AWS Lambda support
- Google Cloud Functions
- Azure Functions
- Serverless deployment

### 2. Advanced Analytics

- Machine learning detection
- Anomaly detection
- Trend analysis
- Predictive modeling

### 3. Collaboration Features

- Multi-user support
- Team workspaces
- Shared scenarios
- Real-time collaboration

### 4. API Integration

- REST API endpoints
- Webhook support
- Third-party integrations
- CI/CD pipeline support
