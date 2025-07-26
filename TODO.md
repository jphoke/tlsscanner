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

## 🚀 High Priority - Next Features

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

### Additional STARTTLS Protocols
- [ ] PostgreSQL (port 5432) - SSLRequest packet
- [ ] MySQL (port 3306) - SSL capability flag
- [ ] LDAP (port 389) - StartTLS extended operation
- [ ] XMPP/Jabber (port 5222)
- [ ] FTP with AUTH TLS (port 21)

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
- [ ] Heartbleed
- [ ] POODLE
- [ ] BEAST
- [ ] CRIME/BREACH
- [ ] ROBOT
- [ ] Logjam
- [ ] FREAK
- [ ] SSL v2/v3 via OpenSSL

### Advanced Analysis
- [ ] Certificate transparency logs
- [ ] OCSP stapling verification
- [ ] DNS CAA record checking
- [ ] HTTP security headers
- [ ] HSTS preload status
- [ ] Certificate pinning detection

### UI/UX Improvements
- [ ] Historical trending graphs
- [ ] Scan comparison tool
- [ ] Mobile app
- [ ] Browser extension
- [ ] Dark/light theme toggle
- [ ] Customizable dashboards

## 🐛 Known Issues

1. Cannot detect SSL v2/v3 (Go crypto/tls limitation)
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