#!/bin/bash

# OWASPChecker Protobuf Tools Installation Script

set -e

echo "Installing protobuf tools for OWASPChecker..."

# Detect OS
OS=$(uname -s)
ARCH=$(uname -m)

case $OS in
    Darwin)
        echo "Detected macOS"
        if command -v brew &> /dev/null; then
            echo "Installing protobuf via Homebrew..."
            brew install protobuf
        else
            echo "Homebrew not found. Please install protobuf manually:"
            echo "  brew install protobuf"
            exit 1
        fi
        ;;
    Linux)
        echo "Detected Linux"
        if command -v apt-get &> /dev/null; then
            echo "Installing protobuf via apt..."
            sudo apt-get update
            sudo apt-get install -y protobuf-compiler
        elif command -v yum &> /dev/null; then
            echo "Installing protobuf via yum..."
            sudo yum install -y protobuf-compiler
        else
            echo "Package manager not found. Please install protobuf manually."
            exit 1
        fi
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Please install protobuf manually for your system."
        exit 1
        ;;
esac

# Install Go protobuf plugins
echo "Installing Go protobuf plugins..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install TypeScript protobuf plugin
echo "Installing TypeScript protobuf plugin..."
cd apps/gui-runner
npm install -g ts-proto

echo "Protobuf tools installation complete!"
echo ""
echo "You can now run:"
echo "  make -f scripts/Makefile proto"
echo "  make -f scripts/Makefile proto-ts"
