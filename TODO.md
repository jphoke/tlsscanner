# TODO List for TLS Scanner Portal

## ✅ Completed (as of 2025-07-26)

### Core Scanner
- [x] Built fast Go-based TLS scanner (<1s scan times)
- [x] Protocol detection (TLS 1.0 - 1.3)
- [x] Cipher suite enumeration with security evaluation
- [x] Certificate validation and chain analysis
- [x] SSL Labs grading methodology implementation
- [x] Grade capping rules (TLS 1.0→C, 3DES→B, RC4→F, no PFS→B)
- [x] TLS 1.3 forward secrecy detection fix
- [x] Grade degradation tracking (shows specific issues)
- [x] Dual grading system (SSL Labs overall + subcategories)
- [x] Handle IP scanning properly
- [x] JSON and text output formats
- [x] Support for non-standard ports

### Web Portal Infrastructure
- [x] REST API with Gin framework
- [x] PostgreSQL database schema with SSL Labs fields
- [x] Redis job queue integration
- [x] Worker pool for concurrent scanning
- [x] WebSocket support for real-time updates
- [x] Docker Compose setup (ports 3000/8000)
- [x] Basic web UI with grade display

### Database & API
- [x] Enhanced database schema with security issue tracking
- [x] Certificate details storage (expiration, issuer, key info)
- [x] Dedicated tables for vulnerabilities and grade degradations
- [x] Weak protocol and cipher tracking tables
- [x] API worker saves all security issues
- [x] getScan endpoint returns complete security assessment
- [x] Database cleanup scripts (Docker-based, reads from .env)

### Web UI
- [x] Professional redesign with dark theme
- [x] SSL Labs score breakdown with visual progress bars
- [x] Security issues section with remediation guidance
- [x] Certificate expiration warnings (expired/critical/warning)
- [x] Recent Scans section with full scan history
- [x] Click-to-view previous scan results
- [x] Unique scan ID display
- [x] Weak protocols and cipher suites display
- [x] Real-time updates via WebSocket

### STARTTLS Support (as of 2025-07-26)
- [x] Automatic protocol detection based on port
- [x] SMTP STARTTLS support (ports 25, 587)
- [x] IMAP STARTTLS support (port 143)
- [x] POP3 STARTTLS support (port 110)
- [x] Auto-detect STARTTLS vs direct TLS connections
- [x] Record service type and connection type in database
- [x] Tested against Gmail SMTP/IMAP servers

### Vulnerability Detection (as of 2025-07-28)
- [x] BEAST Attack detection (TLS 1.0 + CBC ciphers)
- [x] SWEET32 detection (3DES vulnerabilities)
- [x] FREAK Attack detection (Export-grade ciphers)
- [x] RC4 cipher vulnerabilities
- [x] Anonymous cipher suite detection
- [x] Weak DH parameters warning
- [x] CVE tracking with IDs and CVSS scores
- [x] Database schema with JSONB CVE storage
- [x] Web UI vulnerability display with severity

## 🚀 High Priority - Next Features

### zcrypto Migration Testing (Branch: feature/zcrypto-migration)
- [x] Successfully migrated from crypto/tls to zcrypto
- [ ] Test export cipher enumeration capabilities
- [ ] Verify NULL cipher detection works
- [ ] Test browser-specific cipher suite lists
- [ ] Benchmark performance vs standard crypto/tls
- [ ] Document any API differences or quirks found
- [ ] Consider merging to main after thorough testing

### Comments Field for Scans
- [x] Add comments field to scan records (0-100 chars)
  - [x] Database schema update: ALTER TABLE scans ADD COLUMN comments VARCHAR(100)
  - [x] API: Accept comments in POST /scans request
  - [x] API: Return comments in GET /scans responses
  - [x] Web UI: Add comments input field
  - [x] Web UI: Display comments in scan results and recent scans
  - [x] Use cases: Change tickets, test purposes, analyst notes

### Custom Port Mapping
- [ ] Allow admin to configure custom port mappings file
- [ ] Support for non-standard ports (e.g., 8006→HTTPS for Proxmox)
- [ ] JSON/YAML configuration file for custom mappings
- [ ] Check custom mappings before well-known ports

### SSL v3 Raw Socket Implementation (feature/raw-sslv3-sockets)
- [ ] Implement raw socket SSL v3 detection as optional feature
  - [ ] Create raw TCP socket connection handler
  - [ ] Build SSL v3 ClientHello packet construction
  - [ ] Parse ServerHello/Alert responses
  - [ ] Add CLI flag (--check-sslv3 or --legacy-protocols)
  - [ ] Add UI checkbox for "Test legacy SSL protocols"
  - [ ] Integrate with existing vulnerability detection
  - [ ] Add POODLE vulnerability when SSL v3 detected
  - [ ] Document performance impact (~15s per test)
  - [ ] Unit tests for various response scenarios
  - [ ] Integration with SSL Labs scoring (auto F grade)

### Additional STARTTLS Protocols
- [ ] PostgreSQL (port 5432) - SSLRequest packet
- [ ] MySQL (port 3306) - SSL capability flag
- [ ] LDAP (port 389) - StartTLS extended operation
- [ ] XMPP/Jabber (port 5222)
- [x] FTP with AUTH TLS (port 21) - Completed 2025-08-01

### Environment Configuration
- [x] Configurable host ports via environment variables
  - [x] POSTGRES_HOST_PORT (default: 5432)
  - [x] REDIS_HOST_PORT (default: 6379)
  - [x] API_HOST_PORT (default: 8000)
  - [x] WEB_HOST_PORT (default: 3000)
  - [x] Avoid conflicts with existing services
  - [x] Updated .env.example with documentation

### Deployment & Operations
- [ ] Production environment configuration
- [ ] SSL/TLS certificates for portal itself
- [ ] Nginx reverse proxy configuration
- [ ] Monitoring setup (Prometheus/Grafana)
- [ ] PostgreSQL backup strategy
- [ ] Load testing and optimization
- [ ] Security hardening checklist
- [ ] Docker image optimization

## 📈 Medium Priority - Feature Enhancements

### Bulk Operations
- [ ] CSV upload for bulk scanning
- [ ] Background processing with progress
- [ ] Export results to CSV/JSON
- [ ] Batch operations API

### Scheduled Scans
- [ ] Cron-like scheduling system
- [ ] Email notifications for changes
- [ ] Webhook integrations
- [ ] Scan result comparisons

### Reporting
- [ ] PDF report generation
- [ ] Executive summary template
- [ ] Compliance reporting (PCI-DSS, etc.)
- [ ] Custom branding options

### API Enhancements
- [x] OpenAPI/Swagger docs (completed 2025-07-26)
- [ ] JWT authentication
- [ ] API key management
- [ ] Rate limiting per IP/key
- [ ] Usage analytics

## 🔧 Low Priority - Advanced Features

### Additional Protocol Support
- [ ] **XMPP/Jabber STARTTLS** (port 5222)
- [ ] **FTP** with AUTH TLS (port 21)
- [ ] **NNTP** with STARTTLS (port 119)

### Vulnerability Detection
- [x] BEAST (CVE-2011-3389) - TLS 1.0 with CBC ciphers
- [x] SWEET32 (CVE-2016-2183) - 3DES birthday attacks
- [x] FREAK (CVE-2015-0204) - Export-grade ciphers (enhanced with zcrypto)
- [x] RC4 weaknesses (CVE-2013-2566, CVE-2015-2808)
- [x] Anonymous cipher suites detection
- [x] Weak DH parameters warning (Logjam risk)
- [x] CVE tracking with CVSS scores
- [x] Heartbleed (CVE-2014-0160) - Heuristic detection with confidence scoring
- [ ] POODLE (CVE-2014-3566)
- [ ] CRIME/BREACH compression attacks
- [ ] ROBOT (CVE-2017-13099)
- [ ] Full Logjam detection with DH parameter size
- [x] SSL v3 detection code ready (but zcrypto blocks connections)

### New Features Enabled by zcrypto
- [ ] **Export Cipher Enumeration** - Test and enumerate all export-grade ciphers
- [ ] **NULL Cipher Detection** - Identify and test servers with no encryption
- [ ] **Browser Cipher Suite Testing** - Use Chrome/Firefox/Safari cipher lists
- [ ] **Enhanced FREAK Detection** - More accurate with actual export cipher presence
- [ ] **Certificate JSON Export** - Use zcrypto's JSON serialization
- [ ] **DH Parameter Extraction** - Get actual DH sizes from handshake
- [ ] **Extended Handshake Analysis** - Access to handshake messages
- [ ] **Broken Certificate Handling** - Test against malformed certificates

### Advanced Analysis
- [ ] Banner detection and version extraction
  - [ ] Capture SMTP/IMAP/POP3 banners during STARTTLS (already read, just ignored)
  - [ ] Extract OpenSSL/server versions from banners
  - [ ] HTTPS server header capture (may need parallel curl or HTTP client)
  - [ ] Use version info to improve vulnerability detection accuracy
- [ ] Certificate transparency logs
- [ ] OCSP stapling verification
- [ ] DNS CAA record checking
- [ ] HTTP security headers
- [ ] HSTS preload status
- [ ] Certificate pinning detection

### UI/UX Improvements
- [ ] Help/Reference documentation integrated into web UI
  - [ ] Create comprehensive help document covering vulnerability detection, grading methodology, and usage
  - [ ] Serve documentation files through web server
  - [ ] Update vulnerability links to use local documentation instead of GitHub
  - [ ] Include search functionality for help topics
- [ ] Historical trending graphs
- [ ] Scan comparison tool
- [ ] Mobile app
- [ ] Browser extension
- [ ] Dark/light theme toggle
- [ ] Customizable dashboards

## 🐛 Known Issues

1. Cannot detect SSL v2/v3 (zcrypto also blocks SSL v3 despite being a research library)
   - Planned workaround: Raw socket implementation for SSL v3 detection
2. Certificate key size not calculated
3. No client certificate authentication support
4. Full chain validation requires system roots

## 💡 Future Ideas

- Multi-region scanning nodes
- Kubernetes operator
- Terraform provider
- CI/CD pipeline integrations
- Slack/Teams/Discord bots
- GraphQL API
- Machine learning for anomaly detection
- Certificate management features
- DNS-over-HTTPS checking
- QUIC/HTTP3 support