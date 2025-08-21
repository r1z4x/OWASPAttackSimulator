#!/bin/sh

# OWASPChecker All-in-One Startup Script

set -e

echo "Starting OWASPChecker All-in-One..."

# Initialize database if needed
if [ ! -f "/app/data/owaspchecker.db" ]; then
    echo "Initializing database..."
    ./bin/owaspchecker db init
fi

# Start CLI in background
echo "Starting CLI..."
./bin/owaspchecker &
CLI_PID=$!

# Start GUI in background
echo "Starting GUI..."
cd /app/gui
pnpm start &
GUI_PID=$!

# Function to handle shutdown
cleanup() {
    echo "Shutting down..."
    kill $CLI_PID 2>/dev/null || true
    kill $GUI_PID 2>/dev/null || true
    wait
    echo "Shutdown complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Wait for processes
wait
