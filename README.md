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
  - **NEW: Automatic STARTTLS support** for mail servers (SMTP, IMAP, POP3)
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

### Scan mail servers (automatic STARTTLS):
```bash
# SMTP with STARTTLS
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "mail.example.com:587"}'

# IMAP with STARTTLS
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "mail.example.com:143"}'
```

### Get scan results:
```bash
curl http://localhost:8000/api/v1/scans/{scan-id}
```

### List all scans:
```bash
curl http://localhost:8000/api/v1/scans
```

## STARTTLS Support

The scanner automatically detects and handles STARTTLS for mail servers based on port:

| Port | Service | Protocol Type |
|------|---------|---------------|
| 25   | SMTP | STARTTLS |
| 587  | SMTP Submission | STARTTLS |
| 465  | SMTPS | Direct TLS |
| 143  | IMAP | STARTTLS |
| 993  | IMAPS | Direct TLS |
| 110  | POP3 | STARTTLS |
| 995  | POP3S | Direct TLS |

No configuration needed - just provide the target with port and the scanner handles the rest!

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

**Note**: If you're using Docker (recommended), you don't need to install these locally! Docker handles everything for you. Skip to the Quick Start section above.

For local development without Docker, you'll need:
- Go 1.23 or newer (programming language) - [Installation guide below](#installing-go)
- PostgreSQL 15+ (database)
- Redis 7+ (caching/queue)

### Installing Go

**What is Go?** Go (also called Golang) is the programming language this scanner is built with. You need it installed to build the scanner from source.

#### Step-by-Step Go Installation:

1. **Check if Go is already installed:**
   ```bash
   go version
   ```
   If you see something like `go version go1.23.0 darwin/amd64`, you're good! Skip to [Building from source](#building-from-source).

2. **Download Go:**
   - Visit https://go.dev/dl/
   - Find your operating system (Windows, macOS, or Linux)
   - Click the download link for your system
   
   **Not sure which to download?**
   - Windows: Download the `.msi` file
   - macOS: Download the `.pkg` file  
   - Linux: Download the `.tar.gz` file

3. **Install Go:**
   
   **Windows:**
   - Double-click the downloaded `.msi` file
   - Click "Next" through the installer (default settings are fine)
   - Go will be installed to `C:\Program Files\Go`
   
   **macOS:**
   - Double-click the downloaded `.pkg` file
   - Follow the installer prompts
   - Go will be installed to `/usr/local/go`
   
   **Linux:**
   ```bash
   # Remove any previous Go installation
   sudo rm -rf /usr/local/go
   
   # Extract the archive (replace go1.23.0 with your version)
   sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
   
   # Add Go to your PATH (add this to ~/.bashrc or ~/.zshrc)
   export PATH=$PATH:/usr/local/go/bin
   
   # Reload your shell configuration
   source ~/.bashrc  # or source ~/.zshrc
   ```

4. **Verify Go is installed:**
   ```bash
   go version
   ```
   You should see the Go version printed. If not, see [Troubleshooting](#go-installation-troubleshooting).

5. **Set up Go workspace (optional but recommended):**
   ```bash
   # Create a directory for your Go projects
   mkdir -p ~/go/src
   ```

#### Go Installation Troubleshooting

**"go: command not found" error:**
- **Windows**: Restart your command prompt or PowerShell
- **macOS/Linux**: Make sure Go is in your PATH:
  ```bash
  echo $PATH | grep -q "/usr/local/go/bin" || echo "Go not in PATH!"
  ```
  If not in PATH, add to your shell config file (~/.bashrc, ~/.zshrc, etc.):
  ```bash
  export PATH=$PATH:/usr/local/go/bin
  ```

**"Permission denied" errors:**
- Use `sudo` for installation commands on macOS/Linux
- On Windows, run installer as Administrator

**Still having issues?**
- Try the official Go troubleshooting guide: https://go.dev/doc/install
- Or just use Docker instead (see Quick Start section) - no Go installation needed!

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