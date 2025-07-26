# TLS Scanner Portal

A fast, modern web portal for comprehensive TLS/SSL security testing. Built with Go for blazing-fast performance.

## Features

- **Lightning Fast**: Native Go implementation is 10-100x faster than shell-based solutions
- **SSL Labs Grading**: Industry-standard scoring methodology with grade capping
  - Automatic grade caps for weak protocols (TLS 1.0→C)
  - Caps for weak ciphers (3DES→B, RC4→F)
  - Cap for missing forward secrecy (→B)
  - TLS 1.3 forward secrecy properly detected
- **Comprehensive Testing**: 
  - Protocol version detection (TLS 1.0 - TLS 1.3)
  - Cipher suite enumeration with forward secrecy detection
  - Certificate validation with expiration tracking
  - Vulnerability detection (weak protocols, cipher issues)
  - Grade degradation analysis with remediation guidance
- **Professional Web UI**:
  - Visual SSL Labs score breakdown
  - Certificate expiration warnings (critical/warning levels)
  - Security issues with actionable remediation steps
  - Recent scans history with click-to-view
  - Unique scan ID tracking
- **Real-time Updates**: WebSocket support for live scan progress
- **RESTful API**: Full API with Swagger documentation for integration
- **Persistent Storage**: PostgreSQL for scan history and security analysis
- **Queue Management**: Built-in job queue with Redis for scalability
- **Docker Ready**: One-command deployment with docker-compose

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/yourusername/tlsscanner-portal
cd tlsscanner-portal
```

2. Copy environment configuration:
```bash
cp .env.example .env
```

3. Start with Docker Compose:
```bash
docker compose up -d --build
```

4. Access the portal:
- Web UI: http://localhost:3000
- API: http://localhost:8000/api/v1/health
- API Documentation: http://localhost:8000/swagger/index.html

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Web UI    │────▶│   REST API  │────▶│  Go Scanner │
│   (HTML/JS) │     │  (Gin/Go)   │     │   Engine    │
└─────────────┘     └─────────────┘     └─────────────┘
                            │                    │
                            ▼                    ▼
                    ┌─────────────┐     ┌─────────────┐
                    │  PostgreSQL │     │    Redis    │
                    │   Database  │     │    Queue    │
                    └─────────────┘     └─────────────┘
```

## API Usage

### Submit a scan:
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### Get scan results:
```bash
curl http://localhost:8000/api/v1/scans/{scan-id}
```

### List all scans:
```bash
curl http://localhost:8000/api/v1/scans
```

## Performance Comparison

| Tool | Scan Time (avg) | Resource Usage |
|------|----------------|----------------|
| testssl.sh | 60-120s | High (spawns many processes) |
| TLS Scanner Portal | 0.5-2s | Low (single binary) |

## Screenshots

The web UI provides a comprehensive view of your SSL/TLS security posture:
- SSL Labs grade with visual score breakdown
- Security issues with remediation guidance
- Certificate expiration warnings
- Recent scan history

## Development

### Prerequisites
- Go 1.23+
- PostgreSQL 15+
- Redis 7+

### Building from source:
```bash
# Build scanner CLI
go build -o tlsscanner ./cmd/scanner

# Build API server
go build -o api ./cmd/api

# Run tests
go test ./...
```

### Project Structure:
```
tlsscanner-portal/
├── cmd/
│   ├── api/          # API server
│   └── scanner/      # CLI scanner
├── pkg/
│   └── scanner/      # Core scanner library
├── web/
│   └── static/       # Web UI files
├── scripts/
│   ├── schema.sql    # Database schema
│   ├── cleanup-db.sh # Host cleanup script
│   └── docker-db-cleanup.sh # Docker cleanup script
├── docs/             # Swagger API documentation
└── docker-compose.yml
```

## Configuration

Environment variables (set in .env file):
- `DATABASE_URL`: PostgreSQL connection string
- `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`: Database credentials
- `REDIS_URL`: Redis connection string
- `PORT`: API server port (default: 8080)

## Maintenance

### Database Cleanup

Remove old scan data to manage database size:

```bash
# Delete scans older than 7 days
make cleanup-7

# Delete scans older than 30 days
make cleanup-30

# Delete scans older than 90 days
make cleanup-90

# Delete ALL scans (use with caution!)
make cleanup-all

# Or run directly:
./scripts/docker-db-cleanup.sh [7|30|90|ALL]
```

The cleanup script:
- Reads database credentials from your .env file
- Confirms before deleting data
- Removes scans and all related data (vulnerabilities, grade degradations, etc.)
- Optimizes the database after cleanup

## Security Considerations

This tool is designed for authorized security testing only. Please ensure you have permission to scan any targets. The scanner:
- Does not perform intrusive tests
- Respects rate limits
- Validates all input
- Runs in isolated containers

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Roadmap

- [ ] STARTTLS support for mail/database protocols
- [ ] Vulnerability scanning (Heartbleed, POODLE, etc.)
- [ ] Bulk scanning from CSV
- [ ] Scheduled scans with alerts
- [ ] PDF report generation
- [ ] More detailed cipher analysis

## Support

- Issues: https://github.com/yourusername/tlsscanner-portal/issues
- Documentation: https://github.com/yourusername/tlsscanner-portal/wiki