# TLS Scanner Portal

Lightning-fast TLS/SSL security scanner with web UI. Get comprehensive security analysis in seconds, not minutes.

## Background

This project began as a learning exercise to explore Claude Code's capabilities and gain hands-on experience with Go. What started as a simple goal to build a faster TLS scanner for security testing quickly evolved into something more comprehensive.

The traditional bash-based TLS scanners were painfully slow, often taking minutes to complete basic scans. Security teams need tools that match the pace of modern development - fast, API-driven, and deployable anywhere. This scanner delivers sub-second results while providing deeper analysis than most alternatives.

Built with modern security teams in mind, TLS Scanner Portal offers:
- **Speed**: 100x faster than traditional scanners - get results in milliseconds, not minutes
- **Depth**: Enhanced vulnerability detection using zcrypto for research-grade analysis
- **Integration**: REST API and WebSocket support for seamless automation
- **Deployment**: Docker-based architecture runs anywhere your infrastructure lives

## ⚠️ Critical Security Notice

**This tool uses zcrypto, a research-focused library that intentionally disables security features.**

**DO NOT use this codebase for:**
- ❌ **Actual TLS communications or connections**
- ❌ **Building production services that handle TLS**
- ❌ **Any purpose requiring cryptographic security**

The zcrypto library has safety features removed to enable testing of broken, obsolete, and insecure TLS configurations. This makes it perfect for security scanning but completely unsuitable for secure communications.

## Important: Defensive Security Only

This tool is designed exclusively for:
- ✅ Security compliance scanning
- ✅ Internal infrastructure auditing  
- ✅ Identifying misconfigurations before attackers do
- ✅ Monitoring certificate health and expiration

**DO NOT** use this tool for:
- ❌ Scanning infrastructure you don't own or have permission to test
- ❌ Exploiting discovered vulnerabilities
- ❌ Any malicious or unauthorized purposes

This is a defensive security tool - think "security team's best friend," not "hacker's toolkit."

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
<img width="626" height="915" alt="Screenshot 2025-07-29 at 08 05 35" src="https://github.com/user-attachments/assets/29105479-53b9-4ffd-92e0-b556c9dc0a5a" />

  <p><em>Main portal interface - Simple and intuitive scanning</em></p>
</div>

  <br/>

<div align="center">
  <img width="608" height="1133" alt="Screenshot 2025-07-29 at 08 12 12" src="https://github.com/user-attachments/assets/b84e16fc-81b7-48fa-8377-4e6820199c57" />

  <p><em>Output of "badssl.com" showing security issues and remediation steps</em></p>
</div>

 <br/>

<div align="center">
<img width="591" height="592" alt="Screenshot 2025-07-29 at 08 06 34" src="https://github.com/user-attachments/assets/ac7a172d-3cb4-4ee8-ac49-1c3c9373d88b" />

  <p><em>Grade A result demonstrating compliant security configuration</em></p>
</div>

  <br/>

<div align="center">
<img width="591" height="1107" alt="Screenshot 2025-07-29 at 08 07 36" src="https://github.com/user-attachments/assets/aacf4c9a-cfe2-43ad-86ae-d60e68d7223b" />

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
- [Vulnerability Detection](docs/VULNERABILITIES.md) - How vulnerabilities are detected
- [Contributing](docs/CONTRIBUTING.md) - Help improve the scanner

## Acknowledgements

This project uses the following open source libraries:

- [zcrypto](https://github.com/zmap/zcrypto) - A research-focused fork of Go's crypto libraries that enables scanning of legacy and non-compliant TLS configurations. Licensed under Apache 2.0.
- [ZMap Project](https://zmap.io/) - The team behind zcrypto and other excellent security research tools.


Special thanks to the security research community for their work in identifying and documenting TLS vulnerabilities.

## Other Thanks 
- [Anthropic](https://github.com/anthropics) - Seriously though - [Claude Code](https://github.com/anthropics/claude-code) is a game changer 

## License

MIT License - see [LICENSE](LICENSE) file for details.

This project includes third-party libraries. See [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES) for details.
