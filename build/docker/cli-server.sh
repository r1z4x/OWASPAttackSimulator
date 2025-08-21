#!/bin/sh

# OWASPChecker CLI Server Script

set -e

echo "Starting OWASPChecker CLI Server..."

# Show initial status
echo "CLI Server Status:"
echo "✅ OWASPChecker CLI ready"
echo "📊 Available commands:"
echo "   - ./owaspchecker attack --target <url>"
echo "   - ./owaspchecker scenario --file <scenario.yaml>"

# Keep the container running and respond to health checks
while true; do
    # Health check - just show help
    ./owaspchecker --help > /dev/null 2>&1 || true
    sleep 30
done
