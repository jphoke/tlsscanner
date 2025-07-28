# Development Guide

This guide covers the architecture, building from source, and key development workflows for the TLS Scanner Portal.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Building from Source](#building-from-source)
- [Key Design Decisions](#key-design-decisions)
- [Common Development Tasks](#common-development-tasks)
  - [Adding a New Vulnerability Check](#adding-a-new-vulnerability-check)
  - [Testing with Custom CAs](#testing-with-custom-cas)
  - [Adding STARTTLS Protocol](#adding-starttls-protocol)
  - [API Endpoint Addition](#api-endpoint-addition)
- [Testing](#testing)
- [Environment Variables](#environment-variables)
- [Debugging](#debugging)
- [Code Style](#code-style)
- [Troubleshooting](#troubleshooting)
- [Resources](#resources)

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web UI        │────▶│   REST API      │────▶│  Scanner Core   │
│  (Vanilla JS)   │     │  (Gin/Go)       │     │  (Go crypto/tls)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                │                         │
                                ▼                         ▼
                        ┌─────────────────┐     ┌─────────────────┐
                        │   PostgreSQL    │     │     Redis       │
                        │  (Scan History) │     │  (Job Queue)    │
                        └─────────────────┘     └─────────────────┘
```

### Key Components

1. **Scanner Core** (`pkg/scanner/`)
   - TLS connection handling
   - SSL Labs grading algorithm
   - Certificate validation
   - Vulnerability detection
   - STARTTLS negotiation

2. **API Server** (`cmd/api/`)
   - RESTful endpoints
   - WebSocket support
   - Worker pool management
   - Database operations

3. **CLI Tool** (`cmd/scanner/`)
   - Command-line interface
   - Direct scanner access
   - JSON/text output

4. **Web UI** (`web/static/`)
   - Single-page application
   - Real-time updates
   - Responsive design

## Development Setup

### Prerequisites

- Go 1.23+
- Docker & Docker Compose
- Git
- Make (optional)

### Quick Start

```bash
# Clone repository
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner/tlsscanner-portal

# Set up environment
cp .env.example .env

# Start with Docker
docker compose up -d

# Or run locally
go run cmd/api/main.go
```

## Project Structure

```
tlsscanner-portal/
├── cmd/
│   ├── api/          # API server entry point
│   └── scanner/      # CLI tool entry point
├── pkg/
│   ├── scanner/      # Core scanner library
│   │   ├── scanner.go      # Main scanning logic
│   │   ├── protocols.go    # Port/service detection
│   │   └── starttls.go     # STARTTLS protocols
│   ├── database/     # Database layer
│   └── models/       # Data structures
├── internal/
│   └── worker/       # Background job processing
├── web/static/       # Frontend files
├── scripts/          # Database & maintenance
└── docs/             # Documentation
```

## Building from Source

### Scanner CLI

```bash
# Current platform
go build -o tlsscanner ./cmd/scanner

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o tlsscanner-linux ./cmd/scanner
GOOS=darwin GOARCH=amd64 go build -o tlsscanner-mac ./cmd/scanner
GOOS=windows GOARCH=amd64 go build -o tlsscanner.exe ./cmd/scanner
```

### API Server

```bash
# Build server
go build -o api-server ./cmd/api

# Update Swagger docs
swag init -g cmd/api/main.go -o docs/swagger
```

### Docker Images

```bash
# Build all images
docker compose build

# Build specific service
docker compose build api
```

## Key Design Decisions

### SSL Labs Grading

The grading algorithm (`pkg/scanner/scanner.go`) follows SSL Labs methodology:

```go
// Grade calculation weights
Protocol Support: 30%
Key Exchange: 30%
Cipher Strength: 40%

// Grade capping rules
TLS 1.0 → Maximum C
No PFS → Maximum B
3DES → Maximum B
RC4 → Automatic F
```

### STARTTLS Implementation

Port-based automatic protocol detection:

```go
// pkg/scanner/protocols.go
var wellKnownPorts = map[int]ServiceInfo{
    25:  {Protocol: ProtocolSTARTTLS, STARTTLSType: "smtp"},
    587: {Protocol: ProtocolSTARTTLS, STARTTLSType: "smtp"},
    143: {Protocol: ProtocolSTARTTLS, STARTTLSType: "imap"},
    // ...
}
```

### Database Schema

Cascading deletes ensure data integrity:

```sql
-- Main scan table
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    grade VARCHAR(10),
    -- ...
);

-- Related tables reference scan_id
CREATE TABLE scan_vulnerabilities (
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    -- ...
);
```

## Common Development Tasks

### Adding a New Vulnerability Check

1. Edit `pkg/scanner/scanner.go`:
```go
func checkVulnerabilities(result *Result) {
    // Add your check
    if hasVulnerability() {
        result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
            Name:     "New Vulnerability",
            Severity: "HIGH",
            CVEs:     []CVE{{ID: "CVE-2024-XXXX", CVSS: 7.5}},
        })
    }
}
```

2. Add tests in `pkg/scanner/scanner_test.go`

3. Update database schema if needed

### Testing with Custom CAs

For development with internal certificates:

1. **Add test CAs to the custom-ca directory:**
```bash
# Copy your test CA certificates
cp /path/to/test-ca.crt ./custom-ca/
```

2. **Test with CLI:**
```bash
# Build and test
go build -o tlsscanner ./cmd/scanner
./tlsscanner -target internal.test.local:443 -ca-path ./custom-ca -v
```

3. **Test with Docker:**
```bash
# CAs are automatically mounted from ./custom-ca
# Just ensure HOST_CUSTOM_CA_PATH=./custom-ca in .env
docker compose up -d
```

4. **Verify CAs are loaded:**
```bash
# Check API logs
docker compose logs api | grep "Loaded custom CA"
```

### Adding STARTTLS Protocol

1. Define protocol in `pkg/scanner/starttls.go`:
```go
func negotiatePostgreSQLStartTLS(conn net.Conn) error {
    // Implement protocol negotiation
}
```

2. Map ports in `pkg/scanner/protocols.go`:
```go
5432: {Protocol: ProtocolSTARTTLS, STARTTLSType: "postgresql"},
```

3. Add to switch statement in scanner

### API Endpoint Addition

1. Add handler in `cmd/api/main.go`:
```go
// @Summary New endpoint
// @Tags scans
// @Router /api/v1/new-endpoint [get]
func newEndpointHandler(c *gin.Context) {
    // Implementation
}
```

2. Regenerate Swagger: `swag init -g cmd/api/main.go -o docs/swagger`

## Testing

### Unit Tests

```bash
# All tests
go test ./...

# Specific package
go test ./pkg/scanner

# With coverage
go test -cover ./...

# Verbose
go test -v ./...
```

### Writing Tests

```go
func TestGradeCalculation(t *testing.T) {
    tests := []struct {
        name     string
        scores   Scores
        expected string
    }{
        {"Perfect score", Scores{100, 100, 100}, "A+"},
        {"Good score", Scores{90, 85, 80}, "A"},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            grade := calculateGrade(tt.scores)
            if grade != tt.expected {
                t.Errorf("got %s, want %s", grade, tt.expected)
            }
        })
    }
}
```

## Environment Variables

Key environment variables for development:

```bash
# Database
POSTGRES_DB=tlsscanner
POSTGRES_USER=postgres  
POSTGRES_PASSWORD=changeme
DATABASE_URL=postgres://postgres:changeme@postgres/tlsscanner?sslmode=disable

# Port Configuration (customize if needed)
POSTGRES_HOST_PORT=5432
REDIS_HOST_PORT=6379
API_HOST_PORT=8000
WEB_HOST_PORT=3000

# Scanner Settings
SCAN_TIMEOUT=30
CONNECT_TIMEOUT=10
MAX_CONCURRENT_SCANS=10
WORKER_COUNT=3

# Development Mode
GIN_MODE=debug  # or "release" for production

# Custom CA Support
HOST_CUSTOM_CA_PATH=./custom-ca
SCANNER_VERBOSE=false

# Swagger
SWAGGER_HOST=localhost:8000
```

See `.env.example` for all available options.

## Debugging

### Enable Debug Logging

```bash
# API server
export GIN_MODE=debug
go run cmd/api/main.go

# Scanner
go run cmd/scanner/main.go -target example.com -v
```

### Database Queries

```bash
# Connect to database
docker compose exec postgres psql -U postgres tlsscanner

# Useful queries
SELECT target, grade, created_at FROM scans ORDER BY created_at DESC LIMIT 10;
SELECT COUNT(*) as total, grade FROM scans GROUP BY grade;
```

### Performance Profiling

```go
import _ "net/http/pprof"

// In main()
go func() {
    log.Println(http.ListenAndServe("localhost:6060", nil))
}()

// Profile: go tool pprof http://localhost:6060/debug/pprof/profile
```

## Code Style

- Use `gofmt` for formatting
- Follow [Effective Go](https://go.dev/doc/effective_go)
- Write clear, self-documenting code
- Handle errors explicitly
- Add tests for new features

## Troubleshooting

### Port Conflicts

Edit `.env` to use different ports:
```bash
POSTGRES_HOST_PORT=5433
API_HOST_PORT=8001
```

### Module Issues

```bash
go mod tidy
go mod download
go clean -modcache  # If corrupted
```

### Docker Issues

```bash
# Full reset
docker compose down -v
docker compose up -d --build

# View logs
docker compose logs -f api
```

## Resources

- [Go Documentation](https://go.dev/doc/)
- [Gin Web Framework](https://gin-gonic.com/docs/)
- [TLS 1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446)
- [SSL Labs Grading](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)