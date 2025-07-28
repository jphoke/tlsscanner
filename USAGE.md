# TLS Scanner Portal - Usage Guide

This guide covers all the ways to use the TLS Scanner Portal, from the web interface to the API and command-line tools.

## Table of Contents

- [Web Interface](#web-interface)
- [API Usage](#api-usage)
- [Command Line Scanner](#command-line-scanner)
- [Scanning Different Services](#scanning-different-services)
- [Understanding Results](#understanding-results)
- [Common Use Cases](#common-use-cases)

## Web Interface

### Getting Started

1. **Access the Portal**: Navigate to http://localhost:3000 in your web browser
2. **Enter Target**: Type the hostname or IP address you want to scan
3. **Add Comments** (optional): Add up to 100 characters to identify your scan
4. **Start Scan**: Click "Scan" to begin the analysis

### Web UI Features

#### Real-time Scanning
- Progress updates appear as the scan runs
- Results display immediately upon completion
- WebSocket connection provides live updates

#### Recent Scans
- View your scan history in the sidebar
- Click any previous scan to view its results
- Scans are sorted by most recent first

#### Security Analysis
The results page shows:
- **SSL Labs Grade**: Overall security score (A+ to F)
- **Grade Breakdown**: Individual scores for protocols, key exchange, and ciphers
- **Certificate Status**: Validation and expiration warnings
- **Security Issues**: Specific problems with remediation steps
- **Supported Protocols**: List of TLS versions detected
- **Cipher Suites**: All supported ciphers with security indicators

### Examples

```
# Scan a website
example.com

# Scan with custom port
example.com:8443

# Scan with comments for tracking
Target: example.com
Comments: Production server check

# Scan mail server (STARTTLS automatic)
mail.example.com:587
```

## API Usage

The TLS Scanner Portal provides a comprehensive REST API for integration with your tools and workflows.

### API Documentation

Interactive Swagger documentation is available at: http://localhost:8000/swagger/index.html

### Authentication

The API currently does not require authentication. In production, you should implement proper API key authentication.

### Endpoints

#### Submit a Scan

```bash
POST /api/v1/scans
```

Request body:
```json
{
  "target": "example.com",
  "comments": "Optional comment (max 100 chars)"
}
```

Response:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "message": "Scan initiated"
}
```

#### Get Scan Results

```bash
GET /api/v1/scans/{scan_id}
```

Response includes full scan results with:
- Overall grade and subcategory scores
- Certificate details
- Supported protocols and ciphers
- Security vulnerabilities
- Grade degradations with remediation

#### List All Scans

```bash
GET /api/v1/scans
```

Optional query parameters:
- `limit`: Number of results (default: 50)
- `offset`: Pagination offset
- `target`: Filter by target hostname

#### Delete a Scan

```bash
DELETE /api/v1/scans/{scan_id}
```

### API Examples

#### Basic HTTPS Scan
```bash
# Submit scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Get results (replace with actual scan_id)
curl http://localhost:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000
```

#### Mail Server Scan (SMTP)
```bash
# SMTP with STARTTLS (port 587)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "smtp.gmail.com:587", "comments": "Gmail SMTP check"}'

# SMTPS direct TLS (port 465)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "smtp.gmail.com:465"}'
```

#### Batch Scanning Script
```bash
#!/bin/bash
# scan-list.sh - Scan multiple targets

targets=("example.com" "mail.example.com:587" "secure.example.com:443")

for target in "${targets[@]}"; do
  echo "Scanning $target..."
  response=$(curl -s -X POST http://localhost:8000/api/v1/scans \
    -H "Content-Type: application/json" \
    -d "{\"target\": \"$target\"}")
  
  scan_id=$(echo $response | jq -r '.scan_id')
  echo "Scan ID: $scan_id"
  
  # Wait for scan to complete
  sleep 3
  
  # Get results
  curl -s "http://localhost:8000/api/v1/scans/$scan_id" | jq '.grade'
done
```

## Command Line Scanner

The standalone scanner can be used without the web portal for quick checks or integration into scripts.

### Prerequisites

- Go 1.23 or newer installed on your system
- See the [README](README.md#quick-start) for Go installation instructions

### Building the Scanner

```bash
cd tlsscanner-portal
go build -o tlsscanner ./cmd/scanner

# For other platforms (cross-compilation)
GOOS=darwin GOARCH=amd64 go build -o tlsscanner-mac ./cmd/scanner  # macOS Intel
GOOS=darwin GOARCH=arm64 go build -o tlsscanner-mac ./cmd/scanner  # macOS Apple Silicon
GOOS=windows GOARCH=amd64 go build -o tlsscanner.exe ./cmd/scanner # Windows
```

### Basic Usage

```bash
# Scan with formatted output
./tlsscanner -target example.com

# JSON output for parsing
./tlsscanner -target example.com -json

# Custom port
./tlsscanner -target example.com:8443

# Mail server with STARTTLS
./tlsscanner -target mail.example.com:587

# Verbose output
./tlsscanner -target example.com -v

# Custom timeout
./tlsscanner -target example.com -timeout 30s

# Use custom CA certificates
./tlsscanner -target internal.server.com -ca-path ./custom-ca
```

### Command Line Options

- `-target`: The host:port to scan (required)
- `-json`: Output results in JSON format
- `-v`: Verbose output (shows detailed progress)
- `-timeout`: Connection timeout (default: 10s)
- `-ca-path`: Path to directory containing custom CA certificates

### Output Formats

#### Standard Output
```
Scanning example.com:443...

=== TLS Scan Results for example.com ===
Overall Grade: A
Protocol Score: 95 (A)
Key Exchange Score: 90 (A)
Cipher Strength Score: 90 (A)

Supported Protocols:
- TLS 1.2
- TLS 1.3

Certificate:
- Valid
- Expires in 89 days
```

#### JSON Output
```json
{
  "target": "example.com:443",
  "grade": "A",
  "scores": {
    "protocol": 95,
    "key_exchange": 90,
    "cipher_strength": 90
  },
  "protocols": ["TLS 1.2", "TLS 1.3"],
  "certificate": {
    "valid": true,
    "days_remaining": 89
  }
}
```

## Scanning Different Services

### HTTPS Servers

Standard web servers are scanned directly:
```bash
# Default HTTPS port (443)
example.com

# Custom HTTPS port
example.com:8443

# IP address
192.168.1.100

# Hostname with subdomain
api.example.com
```

### Mail Servers

The scanner automatically detects mail protocols based on port:

#### SMTP Servers
```bash
# SMTP with STARTTLS (submission)
smtp.gmail.com:587

# SMTP with STARTTLS (standard)
mail.example.com:25

# SMTPS (direct TLS)
smtp.gmail.com:465
```

#### IMAP Servers
```bash
# IMAP with STARTTLS
imap.gmail.com:143

# IMAPS (direct TLS)
imap.gmail.com:993
```

#### POP3 Servers
```bash
# POP3 with STARTTLS
pop.gmail.com:110

# POP3S (direct TLS)
pop.gmail.com:995
```

### Custom Services

For services on non-standard ports, the scanner will attempt direct TLS:
```bash
# Custom service
custom.example.com:9443

# Database with TLS
postgres.example.com:5432
```

## Understanding Results

### SSL Labs Grading

The scanner uses the official SSL Labs grading methodology:

#### Overall Grade
- **A+**: Exceptional configuration
- **A**: Strong configuration
- **B**: Adequate configuration with minor issues
- **C**: Problematic configuration needing attention
- **F**: Failing configuration with serious issues
- **M**: Certificate hostname mismatch
- **-**: Connection failed

#### Grade Calculation
- 30% Protocol Support Score
- 30% Key Exchange Score
- 40% Cipher Strength Score

#### Grade Caps
Certain issues automatically cap the maximum grade:
- TLS 1.0 support: Capped at C
- 3DES cipher support: Capped at B
- RC4 cipher support: Automatic F
- No forward secrecy: Capped at B
- Certificate issues: Automatic F (or M for hostname mismatch)

### Security Issues

The scanner identifies and explains security problems:

#### Protocol Issues
- **Weak Protocols**: TLS 1.0, TLS 1.1
- **Missing Modern Protocols**: No TLS 1.3 support
- **Legacy Protocol Support**: SSL v3 (if detected via other tools)

#### Cipher Issues
- **Weak Ciphers**: 3DES, RC4
- **Missing Forward Secrecy**: Non-ECDHE/DHE ciphers
- **Weak Key Exchange**: RSA key exchange

#### Certificate Issues
- **Expiration**: Critical (<7 days) or Warning (<30 days)
- **Validation Failures**: Self-signed, untrusted CA
- **Hostname Mismatches**: Certificate doesn't match target

### Remediation Guidance

Each security issue includes specific remediation steps:

```
Issue: TLS 1.0 Support Detected
Impact: Grade capped at C
Remediation: Disable TLS 1.0 in your server configuration

Issue: No Forward Secrecy
Impact: Grade capped at B
Remediation: Enable ECDHE cipher suites in your server configuration
```

## Common Use Cases

### Regular Security Audits

Schedule weekly scans of your infrastructure:
```bash
#!/bin/bash
# weekly-audit.sh

servers=(
  "www.example.com"
  "api.example.com"
  "mail.example.com:587"
)

for server in "${servers[@]}"; do
  curl -X POST http://localhost:8000/api/v1/scans \
    -H "Content-Type: application/json" \
    -d "{\"target\": \"$server\", \"comments\": \"Weekly audit\"}"
done
```

### Pre-deployment Validation

Check SSL configuration before going live:
```bash
# Scan staging environment
./tlsscanner -target staging.example.com -json | jq '.grade'

# Only deploy if grade is A or better
if [ "$grade" = "A" ] || [ "$grade" = "A+" ]; then
  echo "SSL configuration approved for deployment"
else
  echo "SSL configuration needs improvement"
  exit 1
fi
```

### Certificate Expiration Monitoring

Monitor certificates and alert on upcoming expirations:
```bash
# Check certificate expiration
result=$(curl -s http://localhost:8000/api/v1/scans/latest?target=example.com)
days_remaining=$(echo $result | jq '.certificate.days_remaining')

if [ $days_remaining -lt 30 ]; then
  echo "ALERT: Certificate expires in $days_remaining days"
fi
```

### Compliance Reporting

Generate compliance reports for security standards:
```bash
# Export scan data for compliance
curl -s http://localhost:8000/api/v1/scans \
  | jq '[.[] | {
      target: .target,
      grade: .grade,
      scanned_at: .scanned_at,
      compliant: (.grade | . == "A" or . == "A+")
    }]' > compliance-report.json
```

## Best Practices

1. **Regular Scanning**: Schedule regular scans to catch configuration drift
2. **Track Changes**: Use the comments field to track why scans were performed
3. **Monitor Grades**: Alert on any grade below your minimum standard
4. **Certificate Tracking**: Monitor expiration dates with automated alerts
5. **API Integration**: Integrate scanning into your CI/CD pipeline
6. **Bulk Operations**: Use the API for scanning multiple targets efficiently

## Troubleshooting

### Connection Failures
- Verify the target is accessible from the scanner
- Check firewall rules for port access
- Ensure the service supports TLS/SSL

### Unexpected Grades
- Review the grade degradations section
- Check for weak protocols or ciphers
- Verify certificate validity

### Performance Issues
- The scanner typically completes in 0.5-2 seconds
- Longer times may indicate network issues
- Check Redis and PostgreSQL connectivity

## Next Steps

- Review the [API Documentation](http://localhost:8000/swagger/index.html) for full API details
- Check the [Development Guide](docs/DEVELOPMENT.md) to customize the scanner
- See the [Maintenance Guide](docs/MAINTENANCE.md) for database management