# TLS Scanner Portal

A blazing-fast web portal for comprehensive TLS/SSL security testing. Get detailed security analysis in seconds, not minutes.

## ✨ Key Features

- **⚡ Lightning Fast** - 10-100x faster than shell-based tools (0.5-2s vs 60-120s)
- **🏆 SSL Labs Grading** - Industry-standard scoring with proper grade capping
- **📧 Automatic STARTTLS** - Zero-config mail server scanning (SMTP, IMAP, POP3)
- **🔍 Comprehensive Analysis** - Protocols, ciphers, certificates, vulnerabilities
- **🌐 Modern Web UI** - Real-time updates, scan history, actionable insights
- **🔌 RESTful API** - Full Swagger documentation for easy integration
- **🖥️ Standalone CLI** - Use without web portal for scripts and automation
- **🐳 Docker Ready** - Production deployment in minutes

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner/tlsscanner-portal

# Start everything with Docker
docker compose up -d --build

# Access the portal
# Web UI: http://localhost:3000
# API Docs: http://localhost:8000/swagger/index.html
```

That's it! The scanner is now ready to use.

### Standalone CLI

You can also build and use the scanner as a standalone command-line tool:

```bash
# Build the scanner
go build -o tlsscanner ./cmd/scanner

# Run a scan
./tlsscanner -target example.com

# JSON output
./tlsscanner -target example.com -json
```

See the [Usage Guide](USAGE.md#command-line-scanner) for detailed CLI instructions.

## 📸 What It Does

The TLS Scanner Portal provides comprehensive SSL/TLS security analysis for any endpoint:

### Security Grading
- **SSL Labs Grade** (A+ to F) with detailed scoring breakdown
- **Protocol Analysis** - Detection of TLS 1.0 through TLS 1.3
- **Cipher Suite Evaluation** - Strength assessment and forward secrecy detection
- **Certificate Validation** - Expiration tracking and trust chain verification

### Automatic Protocol Detection
The scanner automatically handles various protocols and services:
- **HTTPS** servers on any port
- **Mail servers** with automatic STARTTLS negotiation
  - SMTP (ports 25, 587)
  - IMAP (port 143)
  - POP3 (port 110)
- **Direct TLS** connections (SMTPS, IMAPS, POP3S)
- **Custom services** on non-standard ports

### Security Analysis
- **Vulnerability Detection** - Identifies weak protocols and ciphers
- **Grade Degradation Tracking** - Shows specific issues impacting your grade
- **Remediation Guidance** - Actionable steps to improve security
- **Forward Secrecy Detection** - Including proper TLS 1.3 support

## 📚 Documentation

- [**Usage Guide**](USAGE.md) - Detailed instructions for web UI and API usage
- [**API Reference**](http://localhost:8000/swagger/index.html) - Interactive API documentation
- [**Development Guide**](docs/DEVELOPMENT.md) - Building from source and contributing
- [**Deployment Guide**](docs/DEPLOYMENT.md) - Production deployment instructions
- [**Maintenance Guide**](docs/MAINTENANCE.md) - Database cleanup and administration

## 🏗️ Architecture

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

### Technology Stack
- **Backend**: Go 1.23+ with Gin framework
- **Scanner**: Native Go crypto/tls for maximum performance
- **Database**: PostgreSQL 15+ for scan history
- **Queue**: Redis 7+ for job management
- **Frontend**: Vanilla JavaScript with real-time WebSocket updates
- **Deployment**: Docker Compose with nginx reverse proxy

## 🎯 Use Cases

- **Security Teams**: Regular security assessments and compliance monitoring
- **DevOps**: Pre-deployment SSL/TLS configuration validation
- **System Administrators**: Mail server security verification
- **Compliance**: Ensure systems meet security standards
- **Development**: API integration for automated security testing

## 🤝 Contributing

We welcome contributions! Please see our [Development Guide](docs/DEVELOPMENT.md) for:
- Setting up your development environment
- Code style guidelines
- Testing requirements
- Pull request process

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🛟 Support

- **Issues**: [GitHub Issues](https://github.com/jphoke/tlsscanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jphoke/tlsscanner/discussions)
- **Wiki**: [Project Wiki](https://github.com/jphoke/tlsscanner/wiki)

## 🙏 Acknowledgments

- SSL Labs for the grading methodology
- The Go crypto/tls team for the excellent TLS library
- All contributors who have helped improve this project