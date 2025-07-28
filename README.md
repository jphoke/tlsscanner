# TLS Scanner Portal

Lightning-fast TLS/SSL security scanner with web UI. Get comprehensive security analysis in seconds, not minutes.

## Quick Start

```bash
git clone https://github.com/jphoke/tlsscanner
cd tlsscanner/tlsscanner-portal
docker compose up -d
```

Open http://localhost:3000 - that's it!

## Features

- ⚡ 100x faster than bash-based scanners
- 🏆 SSL Labs grading
- 📧 Automatic STARTTLS for mail servers (additional protocols soon!)
- 🔍 Vulnerability detection with CVE tracking
- 🏢 Custom CA support for internal certificates
- 🌐 Modern web UI with real-time updates

## Screenshots

<div align="center">
  <img width="1199" alt="Screenshot of main portal page" src="https://github.com/user-attachments/assets/81ed1d69-1b93-4af1-a638-ab4706754568" />
  <p><em>Main portal interface - Simple and intuitive scanning</em></p>
</div>

  <br/>

<div align="center">
  <img width="1183" alt="Results for BADSSL.COM" src="https://github.com/user-attachments/assets/fead97a3-3089-4876-a632-446c8b210c90" />
  <p><em>Grade B result showing security issues and remediation steps</em></p>
</div>

 <br/>

<div align="center">
 <img width="1198" alt="Results for www.hoke.org" src="https://github.com/user-attachments/assets/2628b769-5113-44e5-8ee3-5a0669f3ef5e" />
 <p><em>Grade A+ result demonstrating strong security configuration</em></p>
</div>

  <br/>

<div align="center">
  <img width="1179" height="952" alt="Screenshot 2025-07-26 at 17 22 55" src="https://github.com/user-attachments/assets/1d62e1cf-f9dd-4679-97f9-eebc0baa9453" />
  <p><em>Scan results for SMTP/S Connections using STARTTLS</em></p>
</div>

<br/>

<div align="center">
  <img width="1447" alt="Screenshot of Swagger API Documents" src="https://github.com/user-attachments/assets/55960b63-76a6-430d-81c5-311a35db0723" />
  <p><em>Interactive API documentation with Swagger UI</em></p>
</div>

## Basic Usage

### Web Portal
Navigate to http://localhost:3000 and enter any hostname:
- `example.com` - Standard HTTPS scan
- `smtp.gmail.com:587` - SMTP with STARTTLS
- `192.168.1.1` - Internal IP addresses

### Command Line
```bash
# Basic scan
./tlsscanner -target example.com
./tlsscanner -target 192.168.1.1:8443

# JSON output (works with any host:port)
./tlsscanner -target smtp.gmail.com:587 -json

# With custom CA certificates (for internal/corporate CAs)
./tlsscanner -target internal.company.com -ca-path /path/to/ca/certs
```

The scanner automatically detects STARTTLS for mail ports and trusts certificates signed by CAs in the specified directory.

## Next Steps

- [Installation Options](INSTALL.md) - Custom ports, CLI-only, production setup
- [API Documentation](docs/API.md) - REST API integration
- [Contributing](docs/CONTRIBUTING.md) - Help improve the scanner

## License

MIT License - see [LICENSE](LICENSE) file for details.