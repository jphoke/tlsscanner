# TLS Scanner Portal

Lightning-fast TLS/SSL security scanner with web UI. Get comprehensive security analysis in seconds, not minutes.

<img width="1280" height="640" alt="tlsscanner-go-speed" src="https://github.com/user-attachments/assets/a5490b65-9b14-47a3-9b8c-fd46cd55e3da" />

## Quick Start

```bash
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner
docker compose up -d
```

Open http://localhost:3000 and start scanning!

## Features

- ⚡ **100x faster** than bash-based scanners
- 🏆 **SSL Labs grading** with detailed scoring
- 🔍 **Deep vulnerability detection** including Heartbleed, ROBOT, FREAK
- 📧 **Automatic STARTTLS** for mail servers, FTP, and databases
- 🏢 **Enterprise ready** with LDAP/AD integration and custom CA support
- 🌐 **Modern web UI** with real-time WebSocket updates
- 📊 **REST API** for automation and integration

## Usage Examples

### Web Portal
Navigate to http://localhost:3000 and scan any target:
- `google.com` - Standard HTTPS
- `smtp.gmail.com:587` - SMTP with STARTTLS
- `10.0.1.50:8443` - Internal server with custom port

### Command Line
```bash
# Single scan (automatically uses custom-ca directory for trusted CAs)
./tlsscanner -target example.com

# Batch scanning
./tlsscanner -batch targets.csv

# Deep scan with SSL v3 detection
./tlsscanner -target legacy.server.com --check-sslv3

# Use alternative CA directory
./tlsscanner -target internal.corp.com -ca-path /etc/ssl/corporate-cas
```

### API
```bash
# Single scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# Batch scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '[{"target": "site1.com"}, {"target": "site2.com"}]'
```

## Documentation

- **[Installation Guide](INSTALL.md)** - Detailed setup instructions
- **[Configuration Guide](docs/configuration/README.md)** - All configuration options
- **[API Documentation](docs/api/README.md)** - REST API reference
- **[Database Guide](docs/DATABASE.md)** - Schema and migrations
- **[Development Guide](docs/DEVELOPMENT.md)** - Contributing and local setup

## Security Notice

This tool uses [zcrypto](https://github.com/zmap/zcrypto), a research library with security features intentionally disabled. This enables scanning of broken configurations but makes it **unsuitable for secure communications**. Use only for security assessment, never for actual TLS connections.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/jphoke/tlsscanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jphoke/tlsscanner/discussions)