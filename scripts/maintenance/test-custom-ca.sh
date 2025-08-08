#!/bin/bash
#
# Test script for custom CA functionality
# This helps verify that custom CAs are being loaded and used correctly

set -e

echo "=== Custom CA Test Script ==="
echo

# Check if custom-ca directory exists
if [ ! -d "custom-ca" ]; then
    echo "Creating custom-ca directory..."
    mkdir -p custom-ca
fi

# Check for CA certificates
CA_COUNT=$(find custom-ca -name "*.crt" -o -name "*.pem" -o -name "*.cer" -o -name "*.ca" 2>/dev/null | wc -l)
echo "Found $CA_COUNT CA certificate(s) in custom-ca directory"

if [ $CA_COUNT -eq 0 ]; then
    echo
    echo "⚠️  No CA certificates found!"
    echo "Please add your CA certificates to the custom-ca directory"
    echo "Supported extensions: .crt, .pem, .cer, .ca"
    echo
    echo "Example for Active Directory:"
    echo "  certutil -ca.cert custom-ca/ad-root-ca.crt"
    exit 1
fi

# Test with CLI if built
if [ -f "./scanner" ]; then
    echo
    echo "Testing with CLI scanner..."
    echo "Command: ./scanner -target \$TARGET -ca-path ./custom-ca -v"
    echo
    echo "Please provide a target that uses your custom CA:"
    read -p "Target (e.g., internal.server.com): " TARGET
    
    if [ ! -z "$TARGET" ]; then
        ./scanner -target "$TARGET" -ca-path ./custom-ca -v
    fi
else
    echo
    echo "CLI scanner not built. Build it with:"
    echo "  go build -o scanner ./cmd/scanner"
fi

# Test with Docker
if command -v docker &> /dev/null; then
    echo
    echo "Testing with Docker..."
    echo
    
    # Check if services are running
    if docker compose ps | grep -q "api.*running"; then
        echo "✅ API service is running"
        echo
        echo "Your custom CAs are mounted at: /certs/custom-ca"
        echo "To verify they're loaded, check the logs:"
        echo "  docker compose logs api | grep 'Loaded custom CA'"
    else
        echo "⚠️  API service is not running"
        echo "Start it with: docker compose up -d"
    fi
fi

echo
echo "=== Test Complete ==="