# Changelog

All notable changes to TLS Scanner Portal (TLS-GO(ld)) will be documented in this file.

## [Unreleased]

## [1.1.0] - 2025-07-28

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

### Added - 2025-07-26 Morning Session
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

### Fixed - 2025-07-26 Morning Session
- Fixed database grade field size (was VARCHAR(3), now VARCHAR(10))
- Fixed Docker networking issue with localhost/127.0.0.1 scans
- Fixed UI grade display truncation for longer grades
- Added proper CSS escaping for special grade characters

### Changed - 2025-07-26 Morning Session
- Scanner now fails fast on connection errors
- Better error messages for connection and TLS handshake failures

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