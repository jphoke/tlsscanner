# TODO List for TLS Scanner Portal

## ✅ Completed

### Core Scanner
- [x] Built fast Go-based TLS scanner
- [x] Protocol detection (TLS 1.0 - 1.3)
- [x] Cipher suite enumeration with security evaluation
- [x] Certificate validation and chain analysis
- [x] SSL Labs grading methodology implementation
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
- [x] Docker Compose setup
- [x] Basic web UI with grade display

## 🚧 In Progress

- [ ] Testing grade degradation output (storm interrupted)
- [ ] Updating API to save new SSL Labs fields
- [ ] Updating web UI to display SSL Labs scores

## 📋 TODO

### High Priority
- [ ] **STARTTLS Support**
  - [ ] SMTP (ports 25, 587)
  - [ ] IMAP (port 143)
  - [ ] POP3 (port 110)
  - [ ] PostgreSQL (port 5432)
  - [ ] MySQL (port 3306)

- [ ] **SSL v2/v3 Detection**
  - [ ] Shell out to OpenSSL for legacy protocol detection
  - [ ] Auto-fail grades for SSL v2/v3

### Medium Priority
- [ ] **Vulnerability Detection**
  - [ ] Heartbleed
  - [ ] POODLE
  - [ ] BEAST
  - [ ] CRIME
  - [ ] FREAK
  - [ ] Logjam

- [ ] **Enhanced Features**
  - [ ] Bulk scanning from CSV
  - [ ] Scheduled recurring scans
  - [ ] Email alerts for grade changes
  - [ ] PDF report generation
  - [ ] More detailed cipher analysis
  - [ ] OCSP stapling check
  - [ ] HTTP security headers check (for HTTPS)

- [ ] **Performance Improvements**
  - [ ] Parallel cipher testing
  - [ ] Connection pooling
  - [ ] Result caching

### Low Priority
- [ ] **UI Enhancements**
  - [ ] Historical scan comparison
  - [ ] Scan statistics dashboard
  - [ ] Dark mode
  - [ ] Mobile responsive design
  - [ ] Export results

- [ ] **API Features**
  - [ ] API authentication
  - [ ] Rate limiting
  - [ ] Swagger/OpenAPI documentation
  - [ ] Webhooks for scan completion

## 🐛 Known Issues

1. Cannot detect SSL v2/v3 due to Go crypto/tls limitations
2. Certificate key size not calculated yet
3. Full certificate chain validation needs system root CAs

## 💡 Future Ideas

- GraphQL API option
- Kubernetes Helm chart
- Prometheus metrics export
- Integration with CI/CD pipelines
- Slack/Teams notifications
- Multi-region scanning