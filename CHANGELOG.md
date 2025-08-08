# Changelog

All notable changes to TLS Scanner Portal (TLS-GO(ld)) will be documented in this file.

## [Unreleased]

### Added - SSL v3 Raw Socket Detection (Branch: feature/raw-sslv3-sockets)
- **Raw Socket SSL v3 Detection**: Optional detection bypassing Go/zcrypto limitations
  - CLI flag `--check-sslv3` for legacy protocol testing
  - "Deep Scan" checkbox in web UI
  - Automatic F grade for SSL v3
  - POODLE vulnerability detection
  - Database migration required (see docs/MIGRATION.md)
  - ~2-3 second overhead when enabled

### Added - August 2025 Features
- **ROBOT Attack Detection**: Identifies RSA key exchange vulnerabilities (CVE-2017-13099)
- **FTP STARTTLS Support**: AUTH TLS/SSL negotiation on port 21
- **Batch Scanning Support**:
  - CLI: `-batch` or `-b` flag for CSV file input
  - API: POST /api/v1/scans accepts arrays for bulk scanning
  - Up to 100 targets per batch via API
  - CSV format supports per-target SSL v3 checking
- **Linter Compliance**: Fixed all golangci-lint issues
  - Context support for all database operations
  - Proper error handling with errors.Is()
  - Resource cleanup verification

## [1.2.0] - 2025-08-08

### Changed - zcrypto Migration
- **Replaced Go's crypto/tls with zcrypto library** for enhanced security research capabilities
  - Direct replacement approach - no abstraction layer needed
  - Maintains full backward compatibility
  - All existing features continue to work
  - Certificate validation enhanced with manual system CA loading
  - API differences handled (Verify returns 4 values instead of 2)
  
### Added - Enhanced Detection Capabilities (via zcrypto)
- **Export Cipher Detection**: Now enumerates all export-grade ciphers (40-bit RC4, RC2, DES)
  - Enhanced FREAK detection with actual export cipher listing
  - Detects patterns like EXPORT, _40_, and DES40
- **NULL Cipher Detection**: Critical warning for ciphers providing NO ENCRYPTION
  - Automatic F grade for any NULL cipher
  - Clear "PLAINTEXT" warning in description
- **Anonymous Cipher Detection**: Enhanced detection for ciphers with no authentication
  - Detects _anon_, DH_anon, ECDH_anon, ADH patterns
  - Trivial MITM attack warning
- **Weak/Broken Cipher Detection**: 
  - Single DES (56-bit only)
  - RC2 (known weaknesses)
  - IDEA (obsolete)
- **Enhanced Logjam Detection**: Lists all DHE ciphers that may use weak parameters
- **Improved Cipher Strength Evaluation**: New categories for NULL_CIPHER, EXPORT, ANONYMOUS, BROKEN
- **Better Certificate Parsing**: JSON serialization support for certificates
- **Research-Focused Design**: Library designed for security analysis, not production use

### Fixed
- **Duplicate Certificate Expiry Warnings**: Fixed bug where expired certificates showed duplicate warnings in the UI
  - Removed redundant expiry check that was causing "Certificate expired" to appear twice
  - Certificate chain validation now handles all expiry checks in one place
  - Bug introduced during zcrypto migration (our bad!)

### Technical Notes
- SSL v3 detection prepared but blocked even by zcrypto (constant exists but connections refused)
- SSL v2 not supported by zcrypto (no constants found)
- Certificate validation quirk: zcrypto sometimes miscategorizes valid certs as expired
- System CAs must be loaded manually as zcrypto doesn't have SystemCertPool()
- DH parameter size extraction not available through ConnectionState (would require lower-level handshake hooks)

## [1.0.1] - 2025-07-28

### Added - Custom Certificate Authority Support
- **Custom CA Support**: Scanner can now trust internal/corporate CAs
  - Supports Active Directory Certificate Services (AD CS) and other internal CAs
  - Certificates validated against custom CA pool
  - Maintains ability to scan any server (InsecureSkipVerify)
  - CLI flag: `-ca-path /path/to/ca/dir`
  - Docker support via volume mapping
  - Environment configuration:
    - `HOST_CUSTOM_CA_PATH=./custom-ca` (Host directory)
    - `CUSTOM_CA_PATH=/certs/custom-ca` (Container path)
    - `SCANNER_VERBOSE=true` (See loaded CAs)

### Added - Configurable Host Ports
- **Environment-based Port Configuration**: Prevent conflicts with existing services
  - All host ports now configurable via environment variables
  - Default ports remain standard (5432, 6379, 8000, 3000)
  - Configuration in `.env` file:
    - `POSTGRES_HOST_PORT=5432` (PostgreSQL)
    - `REDIS_HOST_PORT=6379` (Redis)
    - `API_HOST_PORT=8000` (API server)
    - `WEB_HOST_PORT=3000` (Web UI)

### Added - Vulnerability Detection
- **Comprehensive TLS Vulnerability Scanning**
  - BEAST Attack detection (CVE-2011-3389) for TLS 1.0 with CBC ciphers
  - SWEET32 detection (CVE-2016-2183, CVE-2016-6329) for 3DES vulnerabilities
  - FREAK Attack detection (CVE-2015-0204) for export-grade ciphers
  - RC4 cipher vulnerability detection (CVE-2013-2566, CVE-2015-2808)
  - Anonymous cipher suite detection (no authentication)
  - Weak DH parameters warning for potential Logjam vulnerability

- **CVE Tracking Integration**
  - Each vulnerability includes relevant CVE identifiers
  - CVSS scores displayed for risk assessment
  - Database schema updated with JSONB CVE data column
  - API returns full vulnerability details with CVE information

- **Enhanced UI Vulnerability Display**
  - Dedicated "Vulnerabilities Detected" section with severity icons
  - Critical/High vulnerabilities shown in red (🔴)
  - Medium vulnerabilities shown in orange (🟠)
  - Low vulnerabilities shown in yellow (🟡)
  - CVE details shown inline with vulnerability descriptions

### Changed
- Scanner now performs deeper protocol and cipher analysis for vulnerability detection
- Web UI displays vulnerabilities prominently after Supported Protocols section

## [1.0.0] - 2025-07-26

### Added - 2025-07-26
- **Comments Field**: Added 100-character comments field to scans for tracking change tickets, test purposes, etc.
  - Database schema updated with comments VARCHAR(100)
  - API accepts and returns comments
  - Web UI shows comment input field and displays comments in results/history
  - Scan ID now visible in Recent Scans section

- **M Grade for Hostname Mismatches**: More informative grading for certificate hostname mismatches
  - Grade "M" instead of "F" for hostname/IP mismatches
  - Preserves actual security score (e.g., M with 87/100)
  - Clear indication of what needs fixing
  - Gray background styling for M grade

- **Connection Failure Handling**: Better UX for failed connections
  - Grade "-" for connection failures (was "ERROR" which truncated)
  - Dark gray background for "-" grade
  - Clear error message box with troubleshooting steps
  - Early connection detection prevents hanging

### Fixed - 2025-07-26
- Fixed database grade field size (was VARCHAR(3), now VARCHAR(10))
- Fixed Docker networking issue with localhost/127.0.0.1 scans
- Fixed UI grade display truncation for longer grades
- Added proper CSS escaping for special grade characters

### Changed - 2025-07-26
- Scanner now fails fast on connection errors
- Better error messages for connection and TLS handshake failures

### Added - 2025-07-26 - STARTTLS Implementation
- **Automatic STARTTLS Support**: Zero-configuration mail server scanning
  - Auto-detects service type based on port number
  - Automatically negotiates STARTTLS for mail servers
  - No user configuration needed - "it just works"
  - Implemented protocols:
    - SMTP (ports 25, 587) with EHLO negotiation
    - IMAP (port 143) with CAPABILITY negotiation
    - POP3 (port 110) with CAPA/STLS negotiation
  - Direct TLS for secure ports (465, 993, 995)

- **Service Type Tracking**
  - Records `service_type` in database (smtp, imap, https, etc.)
  - Records `connection_type` in database (direct-tls or starttls)
  - API returns both fields for audit trail

- **Port-based Protocol Detection**
  - Well-known ports mapped to services
  - Unknown ports default to direct TLS
  - Tested with Gmail, Outlook, and other major providers

### Added - Initial Release Features
- Core TLS scanner with <1s scan times
- SSL Labs grading methodology with grade capping
- Professional web UI with security visualization
- Database persistence with PostgreSQL
- Redis job queue for async scanning
- Docker Compose deployment
- Swagger API documentation
- Database cleanup scripts
- WebSocket support for real-time updates

### Security
- Proper TLS 1.3 forward secrecy detection
- Grade capping for weak protocols (TLS 1.0→C)
- Grade capping for weak ciphers (3DES→B, RC4→F)
- Automatic F grade for certificate issues