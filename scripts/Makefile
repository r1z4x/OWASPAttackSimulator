# OWASPChecker Makefile

# Variables
BINARY_NAME=owaspchecker
CLI_BINARY=apps/cli/$(BINARY_NAME)
GUI_RUNNER_DIR=apps/gui-runner
PROTO_DIR=api/proto
BUILD_DIR=build
DOCKER_DIR=build/docker

# Go variables
GO=go
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
GO_VERSION=$(shell go version | awk '{print $$3}')

# Version
VERSION?=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Docker variables
DOCKER_REGISTRY?=owaspchecker
DOCKER_TAG?=latest

# Default target
.PHONY: all
all: clean proto build test

# Development targets
.PHONY: dev
dev: proto
	@echo "Starting development environment..."
	@echo "Starting CLI..."
	$(GO) run ./apps/cli &
	@echo "Starting GUI Runner..."
	cd $(GUI_RUNNER_DIR) && pnpm dev &
	@echo "Development environment started. Press Ctrl+C to stop."

# Build targets
.PHONY: build
build: proto
	@echo "Building OWASPChecker..."
	$(GO) build $(LDFLAGS) -o $(CLI_BINARY) ./apps/cli
	@echo "Build complete: $(CLI_BINARY)"

.PHONY: build-cli
build-cli: proto
	@echo "Building CLI only..."
	$(GO) build $(LDFLAGS) -o $(CLI_BINARY) ./apps/cli

.PHONY: build-gui
build-gui:
	@echo "Building GUI Runner..."
	cd $(GUI_RUNNER_DIR) && pnpm build

.PHONY: build-all
build-all: build-cli build-gui

# Cross-compilation targets
.PHONY: build-linux
build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./apps/cli

.PHONY: build-windows
build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./apps/cli

.PHONY: build-darwin
build-darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./apps/cli

.PHONY: build-cross
build-cross: build-linux build-windows build-darwin

# Proto targets
.PHONY: proto
proto:
	@echo "Generating protobuf code..."
	@if ! command -v protoc &> /dev/null; then \
		echo "Error: protoc not found. Please install protobuf tools first:"; \
		echo "  ./scripts/install-protobuf.sh"; \
		exit 1; \
	fi
	@if ! command -v protoc-gen-go &> /dev/null; then \
		echo "Error: protoc-gen-go not found. Please install Go protobuf plugins:"; \
		echo "  go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; \
		echo "  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"; \
		exit 1; \
	fi
	@mkdir -p $(PROTO_DIR)/gen
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		--proto_path=$(PROTO_DIR) \
		$(PROTO_DIR)/*.proto
	@echo "Protobuf generation complete"

.PHONY: proto-ts
proto-ts:
	@echo "Generating TypeScript protobuf code..."
	cd $(GUI_RUNNER_DIR) && pnpm proto:generate

# Test targets
.PHONY: test
test:
	@echo "Running tests..."
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Test coverage report: coverage.html"

.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	$(GO) test -v -race ./pkg/...

.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	$(GO) test -v -tags=integration ./...

.PHONY: test-gui
test-gui:
	@echo "Running GUI tests..."
	cd $(GUI_RUNNER_DIR) && pnpm test

.PHONY: test-e2e
test-e2e:
	@echo "Running end-to-end tests..."
	cd $(GUI_RUNNER_DIR) && pnpm test:e2e

# Lint targets
.PHONY: lint
lint:
	@echo "Running linters..."
	golangci-lint run
	cd $(GUI_RUNNER_DIR) && pnpm lint

.PHONY: lint-fix
lint-fix:
	@echo "Fixing lint issues..."
	golangci-lint run --fix
	cd $(GUI_RUNNER_DIR) && pnpm lint:fix

# Format targets
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	gofmt -s -w .
	cd $(GUI_RUNNER_DIR) && pnpm format

# Install targets
.PHONY: install
install: build
	@echo "Installing OWASPChecker..."
	$(GO) install ./apps/cli

.PHONY: install-deps
install-deps:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	cd $(GUI_RUNNER_DIR) && pnpm install

.PHONY: install-protobuf
install-protobuf:
	@echo "Installing protobuf tools..."
	./scripts/install-protobuf.sh

# Docker targets
.PHONY: docker-build
docker-build:
	@echo "Building Docker images..."
	docker build -f $(DOCKER_DIR)/Dockerfile.cli -t $(DOCKER_REGISTRY)/cli:$(DOCKER_TAG) .
	docker build -f $(DOCKER_DIR)/Dockerfile.gui -t $(DOCKER_REGISTRY)/gui:$(DOCKER_TAG) .
	docker build -f $(DOCKER_DIR)/Dockerfile.all-in-one -t $(DOCKER_REGISTRY)/all-in-one:$(DOCKER_TAG) .

.PHONY: docker-run
docker-run:
	@echo "Running with Docker Compose..."
	docker-compose up -d

.PHONY: docker-stop
docker-stop:
	@echo "Stopping Docker containers..."
	docker-compose down

# Database targets
.PHONY: db-init
db-init:
	@echo "Initializing database..."
	$(GO) run ./apps/cli db init

.PHONY: db-migrate
db-migrate:
	@echo "Running database migrations..."
	$(GO) run ./apps/cli db migrate

.PHONY: db-vacuum
db-vacuum:
	@echo "Vacuuming database..."
	$(GO) run ./apps/cli db vacuum

.PHONY: db-stats
db-stats:
	@echo "Database statistics:"
	$(GO) run ./apps/cli db stats

# Plugin targets
.PHONY: plugin-build
plugin-build:
	@echo "Building plugins..."
	$(GO) run ./apps/cli plugin build --src ./plugins

.PHONY: plugin-list
plugin-list:
	@echo "Available plugins:"
	$(GO) run ./apps/cli plugin list

# Run targets
.PHONY: run
run: build
	@echo "Running OWASPChecker..."
	./$(CLI_BINARY)

.PHONY: run-scenario
run-scenario: build
	@echo "Running scenario..."
	./$(CLI_BINARY) run scenario --file configs/scenarios/login_attack.yaml

.PHONY: run-gui
run-gui:
	@echo "Running GUI Runner..."
	cd $(GUI_RUNNER_DIR) && pnpm start

# Clean targets
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(CLI_BINARY)
	rm -rf coverage.out coverage.html
	rm -rf $(PROTO_DIR)/gen
	cd $(GUI_RUNNER_DIR) && pnpm clean

.PHONY: clean-deps
clean-deps:
	@echo "Cleaning dependencies..."
	$(GO) clean -modcache
	cd $(GUI_RUNNER_DIR) && rm -rf node_modules

# Documentation targets
.PHONY: docs
docs:
	@echo "Generating documentation..."
	$(GO) doc -all ./pkg/... > docs/api.md

.PHONY: docs-serve
docs-serve:
	@echo "Serving documentation..."
	cd docs && python3 -m http.server 8000

# Security targets
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	gosec ./...
	npm audit --prefix $(GUI_RUNNER_DIR)

# Release targets
.PHONY: release
release: clean build-cross docker-build
	@echo "Creating release..."
	@mkdir -p $(BUILD_DIR)/release
	cp $(BUILD_DIR)/$(BINARY_NAME)-* $(BUILD_DIR)/release/
	cp configs/scenarios/*.yaml $(BUILD_DIR)/release/
	cp configs/defaults.yaml $(BUILD_DIR)/release/
	@echo "Release created in $(BUILD_DIR)/release/"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all              - Clean, generate proto, build, and test"
	@echo "  dev              - Start development environment"
	@echo "  build            - Build CLI application"
	@echo "  build-cli        - Build CLI only"
	@echo "  build-gui        - Build GUI only"
	@echo "  build-cross      - Build for multiple platforms"
	@echo "  proto            - Generate Go protobuf code"
	@echo "  proto-ts         - Generate TypeScript protobuf code"
	@echo "  test             - Run all tests"
	@echo "  test-unit        - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-gui         - Run GUI tests"
	@echo "  test-e2e         - Run end-to-end tests"
	@echo "  lint             - Run linters"
	@echo "  fmt              - Format code"
	@echo "  install          - Install CLI application"
	@echo "  install-deps     - Install dependencies"
	@echo "  install-protobuf - Install protobuf tools"
	@echo "  docker-build     - Build Docker images"
	@echo "  docker-run       - Run with Docker Compose"
	@echo "  db-init          - Initialize database"
	@echo "  db-migrate       - Run database migrations"
	@echo "  db-vacuum        - Vacuum database"
	@echo "  db-stats         - Show database statistics"
	@echo "  plugin-build     - Build plugins"
	@echo "  plugin-list      - List plugins"
	@echo "  run              - Run CLI application"
	@echo "  run-scenario     - Run sample scenario"
	@echo "  run-gui          - Run GUI application"
	@echo "  clean            - Clean build artifacts"
	@echo "  clean-deps       - Clean dependencies"
	@echo "  docs             - Generate documentation"
	@echo "  security-scan    - Run security scan"
	@echo "  release          - Create release package"
	@echo "  help             - Show this help message"
