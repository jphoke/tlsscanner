# Development Guide

This guide covers setting up your development environment, understanding the codebase, and contributing to the TLS Scanner Portal.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Building from Source](#building-from-source)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Making Changes](#making-changes)
- [Debugging](#debugging)
- [Contributing](#contributing)

## Prerequisites

### Required Software

- **Go 1.23+** - [Installation guide](https://go.dev/doc/install)
- **PostgreSQL 15+** - For database
- **Redis 7+** - For job queue
- **Docker & Docker Compose** - For containerized development
- **Git** - For version control

### Optional Tools

- **Make** - For using Makefile commands
- **jq** - For JSON parsing in scripts
- **curl** - For API testing
- **VS Code** or **GoLand** - Recommended IDEs

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner/tlsscanner-portal
```

### 2. Set Up Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
# Default values work for local development
```

### 3. Install Go Dependencies

```bash
go mod download
go mod verify
```

### 4. Start Development Environment

#### Option A: Docker Development (Recommended)

```bash
# Start all services
docker compose up -d

# Watch logs
docker compose logs -f

# Rebuild after changes
docker compose up -d --build
```

#### Option B: Local Development

```bash
# Start PostgreSQL and Redis (using Docker)
docker run -d --name postgres -p 5432:5432 \
  -e POSTGRES_PASSWORD=password postgres:15

docker run -d --name redis -p 6379:6379 redis:7

# Run database migrations
psql -h localhost -U postgres -f scripts/schema.sql

# Start the API server
go run cmd/api/main.go

# In another terminal, serve the web UI
python3 -m http.server 3000 -d web/static
```

## Project Structure

```
tlsscanner-portal/
├── cmd/
│   ├── api/
│   │   ├── main.go         # API server entry point
│   │   └── docs.go         # Swagger docs generation
│   └── scanner/
│       └── main.go         # CLI scanner entry point
├── pkg/
│   ├── database/
│   │   └── postgres.go     # Database connection and queries
│   ├── models/
│   │   └── scan.go         # Data models
│   └── scanner/
│       ├── scanner.go      # Core scanning logic
│       ├── protocols.go    # Port-to-service mapping
│       └── starttls.go     # STARTTLS negotiation
├── internal/
│   └── worker/
│       └── worker.go       # Background job processing
├── web/
│   └── static/
│       └── index.html      # Web UI (single-page app)
├── scripts/
│   ├── schema.sql          # Database schema
│   └── cleanup-db.sh       # Maintenance scripts
├── docs/
│   ├── swagger/            # API documentation
│   └── *.md                # Documentation files
└── configs/
    └── nginx.conf          # Nginx configuration
```

## Building from Source

### Scanner CLI

```bash
# Build for current platform
go build -o tlsscanner cmd/scanner/main.go

# Cross-compile for multiple platforms
make build-all

# Or manually:
GOOS=linux GOARCH=amd64 go build -o tlsscanner-linux-amd64 cmd/scanner/main.go
GOOS=darwin GOARCH=amd64 go build -o tlsscanner-darwin-amd64 cmd/scanner/main.go
GOOS=windows GOARCH=amd64 go build -o tlsscanner.exe cmd/scanner/main.go
```

### API Server

```bash
# Build API server
go build -o api cmd/api/main.go

# Generate Swagger docs
swag init -g cmd/api/main.go -o docs/swagger
```

## Running Tests

### Unit Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Integration Tests

```bash
# Run integration tests (requires database)
go test -tags=integration ./...
```

### Test Specific Packages

```bash
# Test scanner package
go test ./pkg/scanner/...

# Test with verbose output
go test -v ./pkg/scanner/...
```

## Code Style

### Go Guidelines

1. **Format**: Use `gofmt` (automatically done by most IDEs)
   ```bash
   gofmt -w .
   ```

2. **Linting**: Use `golangci-lint`
   ```bash
   golangci-lint run
   ```

3. **Imports**: Group imports (stdlib, external, internal)
   ```go
   import (
       "fmt"
       "net/http"
       
       "github.com/gin-gonic/gin"
       
       "github.com/jphoke/tlsscanner/pkg/scanner"
   )
   ```

4. **Error Handling**: Always check errors
   ```go
   result, err := scanner.Scan(target)
   if err != nil {
       return fmt.Errorf("scan failed: %w", err)
   }
   ```

### Commit Messages

Follow conventional commits:
```
feat: add STARTTLS support for SMTP
fix: correct TLS 1.3 forward secrecy detection
docs: update API documentation
test: add scanner unit tests
refactor: simplify grade calculation logic
```

## Making Changes

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Write clean, documented code
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run tests
go test ./...

# Test the scanner
go run cmd/scanner/main.go -target example.com

# Test the API
go run cmd/api/main.go
# Then: curl http://localhost:8080/api/v1/health
```

### 4. Update Swagger Docs (if API changed)

```bash
swag init -g cmd/api/main.go -o docs/swagger
```

## Debugging

### API Server Debugging

1. **Enable Debug Logging**
   ```bash
   export GIN_MODE=debug
   go run cmd/api/main.go
   ```

2. **Using Delve Debugger**
   ```bash
   dlv debug cmd/api/main.go
   ```

3. **VS Code Debug Configuration**
   ```json
   {
       "version": "0.2.0",
       "configurations": [
           {
               "name": "Debug API",
               "type": "go",
               "request": "launch",
               "mode": "debug",
               "program": "${workspaceFolder}/cmd/api/main.go"
           }
       ]
   }
   ```

### Scanner Debugging

```bash
# Run with verbose output
go run cmd/scanner/main.go -target example.com -verbose

# Debug with delve
dlv debug cmd/scanner/main.go -- -target example.com
```

### Database Queries

```bash
# Connect to database
docker exec -it tlsscanner-postgres psql -U tlsscanner

# Check recent scans
SELECT id, target, grade, created_at FROM scans ORDER BY created_at DESC LIMIT 10;
```

## Contributing

### Before Submitting

1. **Run Tests**: Ensure all tests pass
2. **Check Formatting**: Run `gofmt`
3. **Update Docs**: Document new features
4. **Test Manually**: Verify functionality works

### Pull Request Process

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to your fork
5. Create a Pull Request with:
   - Clear description of changes
   - Any breaking changes noted
   - Tests for new functionality
   - Updated documentation

### Code Review Guidelines

- Be responsive to feedback
- Keep changes focused and atomic
- Write clear commit messages
- Ensure CI passes

## Common Development Tasks

### Adding a New API Endpoint

1. Define the handler in `cmd/api/main.go`
2. Add Swagger annotations
3. Implement business logic
4. Add tests
5. Regenerate Swagger docs

### Adding Scanner Features

1. Modify `pkg/scanner/scanner.go`
2. Add tests in `pkg/scanner/scanner_test.go`
3. Update CLI in `cmd/scanner/main.go`
4. Document new features

### Modifying Database Schema

1. Update `scripts/schema.sql`
2. Create migration script
3. Update models in `pkg/models/`
4. Test with fresh database

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   lsof -i :8080  # Find process using port
   kill -9 <PID>  # Kill the process
   ```

2. **Database Connection Failed**
   - Check PostgreSQL is running
   - Verify credentials in .env
   - Check connection string

3. **Module Dependencies**
   ```bash
   go mod tidy
   go mod download
   ```

### Getting Help

- Check existing [Issues](https://github.com/jphoke/tlsscanner/issues)
- Join [Discussions](https://github.com/jphoke/tlsscanner/discussions)
- Read the [Wiki](https://github.com/jphoke/tlsscanner/wiki)