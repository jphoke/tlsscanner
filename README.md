# TLS Scanner Portal

A fast, modern web portal for comprehensive TLS/SSL security testing. Built with Go for blazing-fast performance.

## Features

- **Lightning Fast**: Native Go implementation is 10-100x faster than shell-based solutions
- **Comprehensive Testing**: 
  - Protocol version detection (SSL 3.0 - TLS 1.3)
  - Cipher suite enumeration with security evaluation
  - Certificate validation and chain analysis
  - Vulnerability detection (weak protocols, cipher issues)
- **Security Grading**: Automatic A+ to F ratings based on configuration
- **Real-time Updates**: WebSocket support for live scan progress
- **RESTful API**: Full API for integration with CI/CD pipelines
- **Queue Management**: Built-in job queue with Redis for scalability
- **Multiple Protocols**: Support for HTTPS, SMTPS, IMAPS, and more (coming soon)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/yourusername/tlsscanner-portal
cd tlsscanner-portal
```

2. Start with Docker Compose:
```bash
docker-compose up -d
```

3. Access the portal:
- Web UI: http://localhost
- API Documentation: http://localhost:8080/api/v1/health

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
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

### Get scan results:
```bash
curl http://localhost:8080/api/v1/scans/{scan-id}
```

### List all scans:
```bash
curl http://localhost:8080/api/v1/scans
```

## Performance Comparison

| Tool | Scan Time (avg) | Resource Usage |
|------|----------------|----------------|
| testssl.sh | 60-120s | High (spawns many processes) |
| TLS Scanner Portal | 2-10s | Low (single binary) |

## Development

### Prerequisites
- Go 1.21+
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
│   └── schema.sql    # Database schema
└── docker-compose.yml
```

## Configuration

Environment variables:
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `PORT`: API server port (default: 8080)

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