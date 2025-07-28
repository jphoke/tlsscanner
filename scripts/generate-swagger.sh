#!/bin/bash
# Script to generate Swagger documentation with configurable host

# Get SWAGGER_HOST from environment or use default
SWAGGER_HOST=${SWAGGER_HOST:-localhost:8000}

echo "Generating Swagger docs with host: $SWAGGER_HOST"

# Check if swag is installed
if ! command -v swag &> /dev/null; then
    echo "Installing swag..."
    go install github.com/swaggo/swag/cmd/swag@latest
fi

# Update the host in main.go temporarily
# Create a backup of main.go
cp cmd/api/main.go cmd/api/main.go.bak

# Replace the @host line with the configured host
sed -i "s|// @host .*|// @host ${SWAGGER_HOST}|" cmd/api/main.go

# Generate swagger docs
swag init -g cmd/api/main.go -o docs/swagger

# Restore the original main.go
mv cmd/api/main.go.bak cmd/api/main.go

echo "Swagger docs generated successfully with host: $SWAGGER_HOST"