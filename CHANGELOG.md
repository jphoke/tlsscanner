# Changelog

All notable changes to the TLS Scanner Portal project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project setup with Go module structure
- Core TLS scanner library with blazing fast performance (<1s scans)
- Protocol detection for TLS 1.0 through TLS 1.3
- Cipher suite enumeration with strength evaluation
- Certificate validation and chain analysis
- **SSL Labs grading methodology** (2025-07-25):
  - Industry-standard scoring algorithm
  - Three weighted categories: Protocol (30%), Key Exchange (30%), Cipher (40%)
  - Automatic F grade for certificate issues
  - Grade boundaries: A (80+), B (65-79), C (50-64), D (35-49), E (20-34), F (<20)
- **Grade degradation tracking** (2025-07-25):
  - Shows specific ciphers/protocols causing grade reduction
  - Provides impact assessment and remediation steps
  - Categories: protocol, key_exchange, cipher, certificate
- Dual grading system for additional insight:
  - Overall Grade: SSL Labs methodology
  - Protocol/Cipher Grade: Detailed crypto strength
  - Certificate Grade: Trust and validation details
- CLI scanner tool with text and JSON output
- REST API server using Gin framework
- PostgreSQL database with SSL Labs scoring fields
- Redis job queue for async scanning
- Worker pool for concurrent scan processing
- WebSocket support for real-time scan updates
- Basic web UI with visual grade display
- Docker Compose setup for easy deployment
- Support for non-standard ports (e.g., 8443)
- IP address scanning with proper certificate handling

### Changed
- Overall grading now uses SSL Labs methodology instead of simple deduction
- Database schema updated with SSL Labs scoring fields
- Certificate scoring to avoid double-counting penalties
- Improved cipher strength evaluation with SSL Labs scoring

### Fixed
- Compilation errors in scanner package
- Unused variable warnings
- Duplicate code sections in grading functions

### Security
- Input validation on all API endpoints
- Certificate validation includes hostname verification
- Proper handling of self-signed certificates
- Automatic F grade for weak signature algorithms (MD5, SHA1)

### Known Issues
- Cannot detect SSL v2/v3 due to Go crypto/tls limitations
- Certificate key size calculation not yet implemented
- No STARTTLS support yet
- No vulnerability scanning (Heartbleed, POODLE, etc.) yet
- Web UI needs update to show SSL Labs scores and degradations

### API Updates (2025-07-25)
- Worker saves all SSL Labs scoring fields to database
- getScan endpoint returns all scoring fields
- listScans includes SSL Labs category scores

## [0.1.0] - TBD (First Release)
- Initial release