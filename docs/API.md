# API Documentation

The TLS Scanner Portal provides a RESTful API for programmatic access to scanning functionality.

## Table of Contents

- [Base URL](#base-url)
- [Quick Start](#quick-start)
- [Endpoints](#endpoints)
  - [POST /api/v1/scans](#post-apiv1scans)
  - [GET /api/v1/scans/:id](#get-apiv1scansid)
  - [GET /api/v1/scans](#get-apiv1scans)
  - [GET /api/v1/health](#get-apiv1health)
- [Response Formats](#response-formats)
- [Code Examples](#code-examples)
  - [Python](#python)
  - [Node.js](#nodejs)
  - [Shell Script](#shell-script)
- [WebSocket API](#websocket-api-real-time-updates)
- [Rate Limiting](#rate-limiting)
- [Authentication](#authentication)
- [Swagger Documentation](#swagger-documentation)
- [Integration Tips](#integration-tips)
- [Support](#support)

## Base URL

```
http://localhost:8000/api/v1
```

For production: `https://scanner.yourdomain.com/api/v1`

**Note:** The default API port is 8000 but can be customized via the `API_HOST_PORT` environment variable in `.env`. See [INSTALL.md](../INSTALL.md) for configuration details.

## Quick Start

### Start a Scan

```bash
# Basic scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "comments": "Testing API"
  }'

# Response
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "message": "Scan initiated"
}
```

### Check Scan Status

```bash
# Get scan results
curl http://localhost:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000

# Response (completed scan)
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "example.com",
  "grade": "A",
  "status": "completed",
  "comments": "Testing API",
  "created_at": "2025-01-01T12:00:00Z",
  "completed_at": "2025-01-01T12:00:02Z",
  "results": {
    "grade": "A",
    "score": 85,
    "protocol_score": 90,
    "key_exchange_score": 85,
    "cipher_strength_score": 80,
    "certificate": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "not_before": "2025-01-01T00:00:00Z",
      "not_after": "2025-04-01T00:00:00Z",
      "days_remaining": 90,
      "is_valid": true
    },
    "protocols": ["TLS 1.2", "TLS 1.3"],
    "vulnerabilities": []
  }
}
```

## Endpoints

### POST /api/v1/scans

Start a new scan or batch of scans.

**Single Scan Request:**
```json
{
  "target": "example.com:443",
  "comments": "Optional comment (max 100 chars)",
  "check_sslv3": false  // Optional: Enable deep scan for SSL v3 (default: false)
}
```

**Batch Scan Request (up to 100 targets):**
```json
[
  {
    "target": "example.com",
    "comments": "Production server",
    "check_sslv3": false
  },
  {
    "target": "smtp.gmail.com:587",
    "comments": "Mail server"
  },
  {
    "target": "legacy.server.com",
    "check_sslv3": true,
    "comments": "Check for SSL v3"
  }
]
```

**Single Scan Response:**
```json
{
  "id": "uuid",
  "status": "pending",
  "message": "Scan initiated"
}
```

**Batch Scan Response:**
```json
{
  "total": 3,
  "success": 3,
  "failed": 0,
  "scans": [
    {"target": "example.com", "id": "uuid-1", "status": "queued"},
    {"target": "smtp.gmail.com:587", "id": "uuid-2", "status": "queued"},
    {"target": "legacy.server.com", "id": "uuid-3", "status": "queued"}
  ],
  "message": "Batch scan initiated: 3 queued, 0 failed"
}
```

**Example - Scan SMTP server:**
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "smtp.gmail.com:587",
    "comments": "Mail server check"
  }'
```

### GET /api/v1/scans/:id

Get scan results by ID.

**Response:**
```json
{
  "id": "uuid",
  "target": "example.com",
  "status": "completed|pending|failed",
  "grade": "A+|A|B|C|D|E|F|M|-",
  "score": 95,
  "comments": "User comment",
  "created_at": "2025-01-01T12:00:00Z",
  "completed_at": "2025-01-01T12:00:02Z",
  "error": null,
  "results": {
    // Full scan results (when completed)
  }
}
```

### GET /api/v1/scans

List recent scans.

**Query Parameters:**
- `limit` - Number of results (default: 20, max: 100)
- `offset` - Pagination offset (default: 0)
- `target` - Filter by target hostname

**Example:**
```bash
# Get last 10 scans
curl "http://localhost:8000/api/v1/scans?limit=10"

# Get scans for specific target
curl "http://localhost:8000/api/v1/scans?target=example.com"
```

**Response:**
```json
{
  "scans": [
    {
      "id": "uuid",
      "target": "example.com",
      "grade": "A",
      "created_at": "2025-01-01T12:00:00Z",
      "comments": "Regular check"
    }
  ],
  "total": 50,
  "limit": 10,
  "offset": 0
}
```

### GET /api/v1/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-01T12:00:00Z"
}
```

## Response Formats

### Scan Results Object

```json
{
  "grade": "A",
  "score": 85,
  "protocol_score": 90,
  "key_exchange_score": 85,
  "cipher_strength_score": 80,
  "certificate": {
    "subject": "CN=example.com",
    "issuer": "CN=Let's Encrypt Authority X3",
    "not_before": "2025-01-01T00:00:00Z",
    "not_after": "2025-04-01T00:00:00Z",
    "days_remaining": 90,
    "key_type": "RSA",
    "key_bits": 2048,
    "signature_algorithm": "SHA256-RSA",
    "is_valid": true,
    "is_expired": false,
    "is_self_signed": false,
    "hostname_match": true
  },
  "protocols": ["TLS 1.2", "TLS 1.3"],
  "cipher_suites": [
    {
      "name": "TLS_AES_128_GCM_SHA256",
      "protocol": "TLS 1.3",
      "kex": "ECDHE",
      "auth": "RSA",
      "enc": "AES-128-GCM",
      "mac": "SHA256",
      "strength_bits": 128,
      "forward_secrecy": true
    }
  ],
  "vulnerabilities": [
    {
      "name": "BEAST Attack",
      "severity": "HIGH",
      "description": "Server supports TLS 1.0 with CBC ciphers",
      "affected": true,
      "cves": [
        {"id": "CVE-2011-3389", "cvss": 5.9}
      ]
    }
  ],
  "service_type": "https",
  "connection_type": "direct-tls"
}
```

### Error Responses

```json
{
  "error": "Invalid target format",
  "code": "INVALID_TARGET",
  "status": 400
}
```

Common error codes:
- `INVALID_TARGET` - Target format is invalid
- `SCAN_TIMEOUT` - Scan took too long
- `CONNECTION_FAILED` - Could not connect to target
- `INTERNAL_ERROR` - Server error

## Code Examples

### Python

```python
import requests
import time

# Start scan
response = requests.post(
    "http://localhost:8000/api/v1/scans",
    json={"target": "example.com", "comments": "Python test"}
)
scan_id = response.json()["id"]

# Poll for results
while True:
    result = requests.get(f"http://localhost:8000/api/v1/scans/{scan_id}")
    data = result.json()
    
    if data["status"] == "completed":
        print(f"Grade: {data['grade']}")
        print(f"Score: {data['score']}")
        break
    elif data["status"] == "failed":
        print(f"Scan failed: {data['error']}")
        break
    
    time.sleep(1)
```

### Node.js

```javascript
const axios = require('axios');

async function scanTarget(target) {
    // Start scan
    const { data: { id } } = await axios.post(
        'http://localhost:8000/api/v1/scans',
        { target, comments: 'Node.js test' }
    );
    
    // Poll for results
    while (true) {
        const { data } = await axios.get(
            `http://localhost:8000/api/v1/scans/${id}`
        );
        
        if (data.status === 'completed') {
            console.log(`Grade: ${data.grade}`);
            return data;
        } else if (data.status === 'failed') {
            throw new Error(data.error);
        }
        
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

scanTarget('example.com').then(console.log).catch(console.error);
```

### Shell Script

**Note:** Requires `jq` for JSON parsing. Install with:
- Ubuntu/Debian: `sudo apt-get install jq`
- macOS: `brew install jq`
- RHEL/CentOS: `sudo yum install jq`
- Alpine: `apk add jq`

```bash
#!/bin/bash

# Function to scan a target
scan_target() {
    local target=$1
    
    # Start scan
    response=$(curl -s -X POST http://localhost:8000/api/v1/scans \
        -H "Content-Type: application/json" \
        -d "{\"target\": \"$target\"}")
    
    scan_id=$(echo $response | jq -r '.id')
    
    # Poll for results
    while true; do
        result=$(curl -s http://localhost:8000/api/v1/scans/$scan_id)
        status=$(echo $result | jq -r '.status')
        
        if [ "$status" = "completed" ]; then
            echo $result | jq '{target, grade, score}'
            break
        elif [ "$status" = "failed" ]; then
            echo "Scan failed: $(echo $result | jq -r '.error')"
            exit 1
        fi
        
        sleep 1
    done
}

# Scan multiple targets
for target in example.com google.com:443 smtp.gmail.com:587; do
    echo "Scanning $target..."
    scan_target $target
done
```

## WebSocket API (Real-time Updates)

**Note:** The WebSocket endpoint `/api/v1/scans/:id/stream` exists in the code but may not be fully implemented. Check current functionality before using in production.

Connect to WebSocket for real-time scan updates:

```javascript
// Start a scan first
const response = await fetch('http://localhost:8000/api/v1/scans', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({target: 'example.com'})
});
const { id } = await response.json();

// Connect to scan-specific WebSocket
const ws = new WebSocket(`ws://localhost:8000/api/v1/scans/${id}/stream`);

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(`Scan update: ${data.status}`);
};
```

## Rate Limiting

The API currently has no rate limiting. For production deployments, consider implementing rate limits based on IP or API key.

## Authentication

The API currently requires no authentication. For production use, implement one of:
- API key authentication
- JWT tokens
- OAuth 2.0

## Swagger Documentation

Interactive API documentation is available at:
```
http://localhost:8000/swagger/index.html
```

This provides a web interface to explore and test all API endpoints.

## Integration Tips

1. **Batch Scanning**: Start multiple scans concurrently, then collect results
2. **Webhooks**: Poll for completion or implement webhooks for async notifications
3. **Caching**: Cache results for repeated targets to reduce load
4. **Error Handling**: Always handle timeout and connection errors gracefully
5. **Result Storage**: Store scan results in your own database for trending
6. **Custom CAs**: The scanner automatically trusts certificates signed by CAs placed in the `./custom-ca` directory. No API configuration needed - it works transparently

## Support

- GitHub Issues: https://github.com/jphoke/tlsscanner/issues
- API Questions: Use the "api" tag in issues