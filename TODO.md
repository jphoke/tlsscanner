# TODO List for TLS Scanner Portal

## 📝 Recent Updates

See [CHANGELOG.md](CHANGELOG.md) for complete feature history.

## 🚀 High Priority

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
- [ ] **NNTP** with STARTTLS (port 119)

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
- [ ] JWT authentication
- [ ] API key management
- [ ] Rate limiting per IP/key
- [ ] Usage analytics

## 🔧 Low Priority - Advanced Features


### Vulnerability Detection - TODO
- [ ] CRIME/BREACH compression attacks
- [ ] Full Logjam detection with actual DH parameter size extraction

### New Features Enabled by zcrypto - TODO
- [ ] **Certificate JSON Export** - Use zcrypto's JSON serialization for storage
- [ ] **DH Parameter Extraction** - Get actual DH sizes from handshake (not exposed in ConnectionState)
- [ ] **Extended Handshake Analysis** - Access to handshake messages for deeper analysis
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
   - Workaround Implmemented:  Raw socket implementation for SSL v3 detection
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