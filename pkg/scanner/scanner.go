package scanner

import (
	ztls "github.com/zmap/zcrypto/tls"
	zx509 "github.com/zmap/zcrypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"strings"
	"time"
)

type Scanner struct {
	config Config
}

type Config struct {
	Timeout         time.Duration
	MaxConcurrency  int
	FollowRedirects bool
	Verbose         bool
	CustomCAPath    string    // Path to directory containing custom CA certificates
	CustomCAs       *zx509.CertPool  // Pool of custom CAs to use for validation
}

type Result struct {
	Target             string              `json:"target"`
	IP                 string              `json:"ip"`
	Port               string              `json:"port"`
	ServiceType        string              `json:"service_type"`       // "https", "smtp", "imap", etc.
	ConnectionType     string              `json:"connection_type"`    // "direct-tls" or "starttls"
	ScanTime           time.Time           `json:"scan_time"`
	Duration           time.Duration       `json:"duration"`
	SupportedProtocols []ProtocolInfo      `json:"supported_protocols"`
	CipherSuites       []CipherInfo        `json:"cipher_suites"`
	Certificate        *CertificateInfo    `json:"certificate"`
	Vulnerabilities    []VulnerabilityInfo `json:"vulnerabilities"`
	
	// SSL Labs grading (overall)
	Grade              string              `json:"grade"` // Overall SSL Labs grade
	Score              int                 `json:"score"` // Overall SSL Labs score (0-100)
	
	// SSL Labs category scores
	ProtocolSupportScore   int             `json:"protocol_support_score"`   // 30% weight
	KeyExchangeScore       int             `json:"key_exchange_score"`       // 30% weight
	CipherStrengthScore    int             `json:"cipher_strength_score"`    // 40% weight
	
	// Our subcategory grades for additional detail
	ProtocolGrade      string              `json:"protocol_grade"`
	ProtocolScore      int                 `json:"protocol_score"`
	CertificateGrade   string              `json:"certificate_grade"`
	CertificateScore   int                 `json:"certificate_score"`
	
	// Grade degradation reasons
	GradeDegradations  []GradeDegradation  `json:"grade_degradations,omitempty"`
	
	Errors             []string            `json:"errors,omitempty"`
}

type GradeDegradation struct {
	Category    string `json:"category"`    // "protocol", "cipher", "key_exchange", "certificate"
	Issue       string `json:"issue"`       // Brief description
	Details     string `json:"details"`     // Specific items causing the issue
	Impact      string `json:"impact"`      // How much it affects the grade
	Remediation string `json:"remediation"` // How to fix it
}

type ProtocolInfo struct {
	Name    string `json:"name"`
	Version uint16 `json:"version"`
	Enabled bool   `json:"enabled"`
}

type CipherInfo struct {
	ID       uint16 `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Strength string `json:"strength"`
	Forward  bool   `json:"forward_secrecy"`
	AEAD     bool   `json:"aead"`
}

type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names"`
	KeyType            string    `json:"key_type"`
	KeySize            int       `json:"key_size"`
	IsValid            bool      `json:"is_valid"`
	ValidationErrors   []string  `json:"validation_errors,omitempty"`
	Chain              []string  `json:"chain"`
}

type VulnerabilityInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Affected    bool     `json:"affected"`
	CVEs        []CVEInfo `json:"cves,omitempty"`
}

type CVEInfo struct {
	ID    string  `json:"id"`
	CVSS  float64 `json:"cvss"`
}

func New(config Config) *Scanner {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 10
	}
	
	// Load custom CAs if path is provided
	if config.CustomCAPath != "" && config.CustomCAs == nil {
		config.CustomCAs = loadCustomCAs(config.CustomCAPath, config.Verbose)
	}
	
	return &Scanner{config: config}
}

// loadSystemCAs loads system CA certificates
func loadSystemCAs() *zx509.CertPool {
	caPool := zx509.NewCertPool()
	
	// Debug: print when called
	// fmt.Printf("DEBUG: Loading system CAs...\n")
	
	// Common system certificate locations
	systemCertPaths := []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Alpine
		"/etc/pki/tls/certs/ca-bundle.crt",                  // RedHat/CentOS/Fedora
		"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
		"/etc/pki/tls/cert.pem",                             // Old RedHat
		"/usr/local/share/certs/ca-root-nss.crt",            // FreeBSD
		"/etc/ssl/cert.pem",                                 // OpenBSD
		"/System/Library/Keychains/SystemRootCertificates.keychain", // macOS
	}
	
	loaded := false
	for _, path := range systemCertPaths {
		if certData, err := ioutil.ReadFile(path); err == nil {
			if caPool.AppendCertsFromPEM(certData) {
				loaded = true
				break
			}
		}
	}
	
	// Also try loading individual certs from directories
	if !loaded {
		certDirs := []string{
			"/etc/ssl/certs",
			"/usr/local/share/certs",
			"/etc/pki/tls/certs",
		}
		
		for _, dir := range certDirs {
			files, err := filepath.Glob(filepath.Join(dir, "*.crt"))
			if err != nil {
				continue
			}
			pemFiles, _ := filepath.Glob(filepath.Join(dir, "*.pem"))
			files = append(files, pemFiles...)
			
			for _, file := range files {
				if certData, err := ioutil.ReadFile(file); err == nil {
					caPool.AppendCertsFromPEM(certData)
					loaded = true
				}
			}
			if loaded {
				break
			}
		}
	}
	
	return caPool
}

// loadCustomCAs loads custom CA certificates from a directory
func loadCustomCAs(caPath string, verbose bool) *zx509.CertPool {
	// Start with system CAs
	caPool := loadSystemCAs()
	if verbose {
		fmt.Printf("Loaded system CA certificates\n")
	}
	
	// Read all .crt, .pem, and .cer files from the directory
	patterns := []string{"*.crt", "*.pem", "*.cer", "*.ca"}
	for _, pattern := range patterns {
		files, err := filepath.Glob(filepath.Join(caPath, pattern))
		if err != nil {
			if verbose {
				fmt.Printf("Warning: Error reading CA files with pattern %s: %v\n", pattern, err)
			}
			continue
		}
		
		for _, file := range files {
			certData, err := ioutil.ReadFile(file)
			if err != nil {
				if verbose {
					fmt.Printf("Warning: Could not read CA file %s: %v\n", file, err)
				}
				continue
			}
			
			if caPool.AppendCertsFromPEM(certData) {
				if verbose {
					fmt.Printf("Loaded custom CA from %s\n", file)
				}
			} else {
				if verbose {
					fmt.Printf("Warning: Failed to parse CA certificate from %s\n", file)
				}
			}
		}
	}
	
	return caPool
}

func (s *Scanner) ScanTarget(target string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Target:             target,
		ScanTime:           start,
		SupportedProtocols: []ProtocolInfo{},
		CipherSuites:       []CipherInfo{},
		Vulnerabilities:    []VulnerabilityInfo{},
		Errors:             []string{},
	}

	// Parse target
	host, port, err := parseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	result.Port = port
	
	// Auto-detect service type based on port
	serviceInfo := DetectServiceType(port)
	if s.config.Verbose {
		fmt.Printf("Detected service: %s on port %s (Protocol: %v)\n", serviceInfo.Name, port, serviceInfo.Protocol)
	}
	
	// Record what we detected
	result.ServiceType = strings.ToLower(serviceInfo.Name)
	if serviceInfo.Protocol == ProtocolSTARTTLS {
		result.ConnectionType = "starttls"
	} else {
		result.ConnectionType = "direct-tls"
	}

	// Resolve IP
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(ips) > 0 {
		result.IP = ips[0].String()
	}

	// First, test if we can connect at all
	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}
	testConn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		// Connection failed - return - grade
		result.Errors = append(result.Errors, fmt.Sprintf("Connection failed: %v", err))
		result.Grade = "-"
		result.Score = 0
		result.Duration = time.Since(start)
		return result, nil
	}
	testConn.Close()

	// Now test if TLS is available
	var tlsConn *ztls.Conn
	tlsConfig := &ztls.Config{
		InsecureSkipVerify: true,
	}
	
	if serviceInfo.Protocol == ProtocolSTARTTLS {
		// Use STARTTLS negotiation
		tlsConn, err = DialWithStartTLS(host, port, serviceInfo.STARTTLSType, tlsConfig, s.config.Timeout)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("STARTTLS negotiation failed: %v", err))
			result.Grade = "-"
			result.Score = 0
			result.Duration = time.Since(start)
			return result, nil
		}
	} else {
		// Direct TLS connection
		tlsConn, err = ztls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
		if err != nil {
			// TCP works but TLS doesn't - still - grade
			result.Errors = append(result.Errors, fmt.Sprintf("TLS handshake failed: %v", err))
			result.Grade = "-"
			result.Score = 0
			result.Duration = time.Since(start)
			return result, nil
		}
	}
	tlsConn.Close()

	// Test protocols
	// Note: Go's crypto/tls doesn't support SSL v2, and SSL v3 support was removed in Go 1.14+
	// This means we cannot detect if a server supports these ancient protocols
	protocols := []struct {
		name    string
		version uint16
	}{
		{"SSL 3.0", ztls.VersionSSL30}, // Won't actually work in modern Go
		{"TLS 1.0", ztls.VersionTLS10},
		{"TLS 1.1", ztls.VersionTLS11},
		{"TLS 1.2", ztls.VersionTLS12},
		{"TLS 1.3", ztls.VersionTLS13},
	}

	for _, proto := range protocols {
		info := ProtocolInfo{
			Name:    proto.name,
			Version: proto.version,
		}
		
		if s.testProtocol(host, port, proto.version, serviceInfo) {
			info.Enabled = true
			result.SupportedProtocols = append(result.SupportedProtocols, info)
			
			// Get ciphers for this protocol
			ciphers := s.getCiphersForProtocol(host, port, proto.version, proto.name, serviceInfo)
			result.CipherSuites = append(result.CipherSuites, ciphers...)
		}
	}

	// Get certificate info
	certInfo, err := s.getCertificateInfo(host, port, serviceInfo)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Certificate error: %v", err))
	} else {
		result.Certificate = certInfo
	}

	// Check vulnerabilities
	result.Vulnerabilities = s.checkVulnerabilities(host, port, result)

	// Calculate grades and scores
	calculateGrades(result)

	result.Duration = time.Since(start)
	return result, nil
}

func (s *Scanner) testProtocol(host, port string, version uint16, serviceInfo ServiceInfo) bool {
	if s.config.Verbose && version == ztls.VersionSSL30 {
		fmt.Printf("DEBUG: Testing SSL v3 protocol (version=0x%04x)\n", version)
	}
	
	tlsConfig := &ztls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	}
	
	var conn *ztls.Conn
	var err error
	
	if serviceInfo.Protocol == ProtocolSTARTTLS {
		// Use STARTTLS negotiation
		conn, err = DialWithStartTLS(host, port, serviceInfo.STARTTLSType, tlsConfig, s.config.Timeout)
	} else {
		// Direct TLS connection
		dialer := &net.Dialer{
			Timeout: s.config.Timeout,
		}
		target := net.JoinHostPort(host, port)
		conn, err = ztls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	}
	
	if err != nil {
		if s.config.Verbose && version == ztls.VersionSSL30 {
			fmt.Printf("DEBUG: SSL v3 test failed: %v\n", err)
		}
		return false
	}
	defer conn.Close()
	
	return true
}

func (s *Scanner) getCiphersForProtocol(host, port string, version uint16, protoName string, serviceInfo ServiceInfo) []CipherInfo {
	var ciphers []CipherInfo
	
	// Get appropriate cipher suites for the protocol version
	var testCiphers []uint16
	for _, suite := range ztls.CipherSuites() {
		if version == ztls.VersionTLS13 {
			// TLS 1.3 ciphers
			if suite.ID&0xff00 == 0x1300 {
				testCiphers = append(testCiphers, suite.ID)
			}
		} else {
			// TLS 1.2 and below
			if suite.ID&0xff00 != 0x1300 {
				testCiphers = append(testCiphers, suite.ID)
			}
		}
	}
	
	// Also test insecure ciphers
	for _, suite := range ztls.InsecureCipherSuites() {
		if version != ztls.VersionTLS13 {
			testCiphers = append(testCiphers, suite.ID)
		}
	}
	
	target := net.JoinHostPort(host, port)
	
	for _, cipherID := range testCiphers {
		tlsConfig := &ztls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			CipherSuites:       []uint16{cipherID},
			InsecureSkipVerify: true,
		}
		
		var conn *ztls.Conn
		var err error
		
		if serviceInfo.Protocol == ProtocolSTARTTLS {
			// Use STARTTLS negotiation
			conn, err = DialWithStartTLS(host, port, serviceInfo.STARTTLSType, tlsConfig, s.config.Timeout)
		} else {
			// Direct TLS connection
			dialer := &net.Dialer{
				Timeout: s.config.Timeout,
			}
			conn, err = ztls.DialWithDialer(dialer, "tcp", target, tlsConfig)
		}
		
		if err == nil {
			defer conn.Close()
			
			// Get cipher name
			cipherName := getCipherName(cipherID)
			
			ciphers = append(ciphers, CipherInfo{
				ID:       cipherID,
				Name:     cipherName,
				Protocol: protoName,
				Strength: evaluateCipherStrength(cipherName),
				Forward:  hasForwardSecrecy(cipherName),
				AEAD:     isAEADCipher(cipherName),
			})
		}
	}
	
	return ciphers
}

func (s *Scanner) getCertificateInfo(host, port string, serviceInfo ServiceInfo) (*CertificateInfo, error) {
	tlsConfig := &ztls.Config{
		InsecureSkipVerify: true,
	}
	
	var conn *ztls.Conn
	var err error
	
	if serviceInfo.Protocol == ProtocolSTARTTLS {
		// Use STARTTLS negotiation
		conn, err = DialWithStartTLS(host, port, serviceInfo.STARTTLSType, tlsConfig, s.config.Timeout)
	} else {
		// Direct TLS connection
		dialer := &net.Dialer{
			Timeout: s.config.Timeout,
		}
		target := net.JoinHostPort(host, port)
		conn, err = ztls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	}
	
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	
	cert := state.PeerCertificates[0]
	
	info := &CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		IsValid:            true,
		ValidationErrors:   []string{},
		Chain:              []string{},
	}
	
	// Key information
	if cert.PublicKeyAlgorithm == cert.PublicKeyAlgorithm {
		info.KeyType = cert.PublicKeyAlgorithm.String()
		// Key size calculation would go here based on key type
	}
	
	// Build certificate chain
	for _, c := range state.PeerCertificates {
		info.Chain = append(info.Chain, c.Subject.String())
	}
	
	// Validation - basic checks
	now := time.Now()
	if now.Before(cert.NotBefore) {
		info.IsValid = false
		info.ValidationErrors = append(info.ValidationErrors, "Certificate not yet valid")
	}
	// Note: Expiry check removed here to avoid duplication
	// validateCertificateChain handles expiry validation comprehensively
	
	// Check hostname
	if err := cert.VerifyHostname(host); err != nil {
		info.IsValid = false
		info.ValidationErrors = append(info.ValidationErrors, fmt.Sprintf("Hostname verification failed: %v", err))
	}
	
	// Perform certificate chain validation with custom CAs
	s.validateCertificateChain(cert, state.PeerCertificates, host, info)
	
	return info, nil
}

// validateCertificateChain performs certificate chain validation with custom CAs
func (s *Scanner) validateCertificateChain(cert *zx509.Certificate, chain []*zx509.Certificate, host string, info *CertificateInfo) {
	// Use custom CA pool if available, otherwise use system pool
	var rootCAs *zx509.CertPool
	if s.config.CustomCAs != nil {
		rootCAs = s.config.CustomCAs
	} else {
		rootCAs = loadSystemCAs()
	}
	
	// Create intermediate pool
	intermediates := zx509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediates.AddCert(chain[i])
	}
	
	// Verify certificate chain
	opts := zx509.VerifyOptions{
		DNSName:       host,
		Roots:         rootCAs,
		Intermediates: intermediates,
	}
	
	currentChains, expiredChains, neverChains, err := cert.Verify(opts)
	
	// Debug output
	if s.config.Verbose {
		fmt.Printf("DEBUG: Verify results - current: %d, expired: %d, never: %d, err: %v\n", 
			len(currentChains), len(expiredChains), len(neverChains), err)
		fmt.Printf("DEBUG: Certificate dates - NotBefore: %v, NotAfter: %v\n", cert.NotBefore, cert.NotAfter)
		fmt.Printf("DEBUG: Current time: %v\n", time.Now())
	}
	
	// zcrypto returns chains in different buckets - check current chains first
	if len(currentChains) > 0 {
		// Certificate is currently valid
		info.IsValid = true
	} else if len(expiredChains) > 0 {
		// Handle expired chains first (before checking err)
		// zcrypto sometimes incorrectly categorizes valid certs as expired
		// Check if the cert is actually within its validity period
		now := time.Now()
		if now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
			// Certificate is actually valid despite zcrypto's categorization
			info.IsValid = true
			if s.config.Verbose {
				fmt.Printf("DEBUG: Certificate is within validity period despite being in expired bucket\n")
			}
		} else {
			// Certificate chain is truly expired
			info.IsValid = false
			info.ValidationErrors = append(info.ValidationErrors, "Certificate chain has expired")
		}
	} else if len(neverChains) > 0 {
		// Certificate chain was never valid
		info.IsValid = false
		info.ValidationErrors = append(info.ValidationErrors, "Certificate chain was never valid")
	} else if err != nil {
		// Check if it's a self-signed certificate
		if cert.Subject.String() == cert.Issuer.String() {
			// It's self-signed, but let's check if it's in our custom CA pool
			if s.config.CustomCAs != nil {
				// Try to verify as a root CA
				opts.Roots = s.config.CustomCAs
				opts.DNSName = "" // Root CAs don't need hostname verification
				currentCustom, _, _, customErr := cert.Verify(opts)
				if customErr == nil && len(currentCustom) > 0 {
					// It's a trusted root CA from our custom pool
					// Don't mark as invalid, just note it's a root CA
					info.ValidationErrors = append(info.ValidationErrors, "Root CA certificate (trusted via custom CA)")
					return
				}
			}
			// It's truly self-signed and not in our trust store
			info.IsValid = false
			info.ValidationErrors = append(info.ValidationErrors, "Self-signed certificate")
		} else {
			// Certificate chain validation failed for other reasons
			info.IsValid = false
			if strings.Contains(err.Error(), "unknown authority") {
				info.ValidationErrors = append(info.ValidationErrors, "Certificate signed by unknown CA")
			} else {
				info.ValidationErrors = append(info.ValidationErrors, fmt.Sprintf("Certificate chain validation failed: %v", err))
			}
		}
	} else {
		// Certificate chain is valid
		// If we have custom CAs and the chain validated, it might be from our custom CA
		if s.config.CustomCAs != nil && len(currentChains) > 0 {
			// Check if the root is from our custom CA (not system)
			systemPool := loadSystemCAs()
			if systemPool != nil {
				// Try with only system pool
				opts.Roots = systemPool
				currentSys, _, _, sysErr := cert.Verify(opts)
				if sysErr != nil || len(currentSys) == 0 {
					// It validated with custom CAs but not system CAs
					info.ValidationErrors = append(info.ValidationErrors, "Certificate trusted via custom CA")
				}
			}
		}
	}
}

func (s *Scanner) checkVulnerabilities(host, port string, result *Result) []VulnerabilityInfo {
	vulns := []VulnerabilityInfo{}
	
	// BEAST - TLS 1.0 with CBC ciphers
	hasTLS10 := false
	for _, proto := range result.SupportedProtocols {
		if proto.Enabled && proto.Version == ztls.VersionTLS10 {
			hasTLS10 = true
			break
		}
	}
	
	if hasTLS10 {
		// Check for CBC ciphers with TLS 1.0
		for _, cipher := range result.CipherSuites {
			if cipher.Protocol == "TLS 1.0" && strings.Contains(cipher.Name, "CBC") {
				vulns = append(vulns, VulnerabilityInfo{
					Name:        "BEAST Attack",
					Severity:    "HIGH",
					Description: "TLS 1.0 with CBC mode ciphers is vulnerable to BEAST attack - allows decryption of HTTPS requests",
					Affected:    true,
					CVEs: []CVEInfo{
						{ID: "CVE-2011-3389", CVSS: 5.9},
					},
				})
				break
			}
		}
	}
	
	// SWEET32 - 3DES vulnerability
	for _, cipher := range result.CipherSuites {
		if strings.Contains(cipher.Name, "3DES") {
			vulns = append(vulns, VulnerabilityInfo{
				Name:        "SWEET32 Birthday Attack",
				Severity:    "HIGH",
				Description: "3DES cipher suites are vulnerable to SWEET32 birthday attacks - can decrypt traffic after ~32GB of data",
				Affected:    true,
				CVEs: []CVEInfo{
					{ID: "CVE-2016-2183", CVSS: 7.5},
					{ID: "CVE-2016-6329", CVSS: 5.3},
				},
			})
			break
		}
	}
	
	// FREAK - Export cipher suites (enhanced with zcrypto)
	exportCiphers := []string{}
	for _, cipher := range result.CipherSuites {
		if strings.Contains(cipher.Name, "EXPORT") || strings.Contains(cipher.Name, "_40_") || strings.Contains(cipher.Name, "DES40") {
			exportCiphers = append(exportCiphers, cipher.Name)
		}
	}
	if len(exportCiphers) > 0 {
		desc := fmt.Sprintf("Export-grade cipher suites detected (%d found): %s - 40-bit encryption can be broken in minutes",
			len(exportCiphers), strings.Join(exportCiphers, ", "))
		if len(exportCiphers) > 3 {
			desc = fmt.Sprintf("Export-grade cipher suites detected (%d found, e.g., %s) - 40-bit encryption can be broken in minutes",
				len(exportCiphers), exportCiphers[0])
		}
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "FREAK Attack",
			Severity:    "CRITICAL",
			Description: desc,
			Affected:    true,
			CVEs: []CVEInfo{
				{ID: "CVE-2015-0204", CVSS: 7.5},
			},
		})
	}
	
	// NULL cipher detection - NO ENCRYPTION!
	nullCiphers := []string{}
	for _, cipher := range result.CipherSuites {
		if strings.Contains(cipher.Name, "NULL") {
			nullCiphers = append(nullCiphers, cipher.Name)
		}
	}
	if len(nullCiphers) > 0 {
		desc := fmt.Sprintf("NULL cipher suites provide NO ENCRYPTION (%d found): %s - All traffic is sent in PLAINTEXT!",
			len(nullCiphers), strings.Join(nullCiphers, ", "))
		if len(nullCiphers) > 3 {
			desc = fmt.Sprintf("NULL cipher suites provide NO ENCRYPTION (%d found) - All traffic is sent in PLAINTEXT!",
				len(nullCiphers))
		}
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "NULL Cipher Suites",
			Severity:    "CRITICAL",
			Description: desc,
			Affected:    true,
			CVEs: []CVEInfo{
				// No specific CVE but automatic F grade
			},
		})
	}
	
	// RC4 vulnerabilities
	for _, cipher := range result.CipherSuites {
		if strings.Contains(cipher.Name, "RC4") {
			vulns = append(vulns, VulnerabilityInfo{
				Name:        "RC4 Cipher Suites",
				Severity:    "HIGH",
				Description: "RC4 cipher suites have multiple vulnerabilities and are considered cryptographically broken",
				Affected:    true,
				CVEs: []CVEInfo{
					{ID: "CVE-2013-2566", CVSS: 5.3},
					{ID: "CVE-2015-2808", CVSS: 5.3},
				},
			})
			break
		}
	}
	
	// Anonymous cipher suites (enhanced detection)
	anonCiphers := []string{}
	for _, cipher := range result.CipherSuites {
		// Check for anonymous key exchange (no authentication)
		if strings.Contains(cipher.Name, "_anon_") || strings.Contains(cipher.Name, "DH_anon") || 
		   strings.Contains(cipher.Name, "ECDH_anon") || strings.Contains(cipher.Name, "ADH") {
			anonCiphers = append(anonCiphers, cipher.Name)
		}
	}
	if len(anonCiphers) > 0 {
		desc := fmt.Sprintf("Anonymous cipher suites provide NO AUTHENTICATION (%d found): %s - Trivial MITM attacks!",
			len(anonCiphers), strings.Join(anonCiphers, ", "))
		if len(anonCiphers) > 3 {
			desc = fmt.Sprintf("Anonymous cipher suites provide NO AUTHENTICATION (%d found) - Trivial MITM attacks!",
				len(anonCiphers))
		}
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "Anonymous Cipher Suites",
			Severity:    "CRITICAL",
			Description: desc,
			Affected:    true,
			// No specific CVE - this is a fundamental protocol weakness
		})
	}
	
	// Weak/Broken ciphers (DES, RC2, IDEA)
	brokenCiphers := []string{}
	for _, cipher := range result.CipherSuites {
		// Single DES (56-bit), RC2, IDEA
		if (strings.Contains(cipher.Name, "DES_CBC") && !strings.Contains(cipher.Name, "3DES")) ||
		   strings.Contains(cipher.Name, "RC2") ||
		   strings.Contains(cipher.Name, "IDEA") {
			brokenCiphers = append(brokenCiphers, cipher.Name)
		}
	}
	if len(brokenCiphers) > 0 {
		desc := fmt.Sprintf("Broken/obsolete cipher suites detected (%d found): %s - These ciphers are cryptographically weak",
			len(brokenCiphers), strings.Join(brokenCiphers, ", "))
		if len(brokenCiphers) > 3 {
			desc = fmt.Sprintf("Broken/obsolete cipher suites detected (%d found, e.g., %s) - These ciphers are cryptographically weak",
				len(brokenCiphers), brokenCiphers[0])
		}
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "Weak/Broken Cipher Suites",
			Severity:    "HIGH",
			Description: desc,
			Affected:    true,
			CVEs: []CVEInfo{
				// DES is only 56-bit, RC2 has known weaknesses, IDEA is obsolete
			},
		})
	}
	
	// Weak DH parameters warning (enhanced Logjam check)
	dheCiphers := []string{}
	for _, cipher := range result.CipherSuites {
		if strings.Contains(cipher.Name, "DHE") && !strings.Contains(cipher.Name, "ECDHE") {
			dheCiphers = append(dheCiphers, cipher.Name)
		}
	}
	
	if len(dheCiphers) > 0 {
		desc := fmt.Sprintf("DHE cipher suites detected (%d found): %s - May use weak DH parameters (< 2048 bits)",
			len(dheCiphers), strings.Join(dheCiphers, ", "))
		if len(dheCiphers) > 3 {
			desc = fmt.Sprintf("DHE cipher suites detected (%d found) - May use weak DH parameters (< 2048 bits), vulnerable to Logjam",
				len(dheCiphers))
		}
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "Weak DH Parameters (Logjam Risk)",
			Severity:    "MEDIUM",
			Description: desc,
			Affected:    true,
			CVEs: []CVEInfo{
				{ID: "CVE-2015-4000", CVSS: 3.7},
			},
		})
	}
	
	// Deprecated protocols (TLS 1.0/1.1)
	deprecatedProtos := []string{}
	for _, proto := range result.SupportedProtocols {
		if proto.Enabled && (proto.Version == ztls.VersionTLS10 || proto.Version == ztls.VersionTLS11) {
			deprecatedProtos = append(deprecatedProtos, proto.Name)
		}
	}
	
	if len(deprecatedProtos) > 0 {
		// Build CVE list based on which protocols are enabled
		cves := []CVEInfo{}
		for _, proto := range deprecatedProtos {
			if proto == "TLS 1.0" {
				// TLS 1.0 has many vulnerabilities
				cves = append(cves, CVEInfo{ID: "CVE-2011-3389", CVSS: 5.9}) // BEAST
				cves = append(cves, CVEInfo{ID: "CVE-2014-3566", CVSS: 4.3}) // POODLE variant
				cves = append(cves, CVEInfo{ID: "CVE-2015-0204", CVSS: 7.5}) // FREAK
				cves = append(cves, CVEInfo{ID: "CVE-2015-4000", CVSS: 3.7}) // Logjam
				cves = append(cves, CVEInfo{ID: "CVE-2016-2107", CVSS: 5.9}) // Padding oracle
			}
		}
		
		// Build description based on CVE count
		desc := fmt.Sprintf("Deprecated protocols enabled: %s - should be disabled for PCI compliance", strings.Join(deprecatedProtos, ", "))
		if len(cves) > 5 {
			// Show summary for many CVEs
			desc = fmt.Sprintf("%s. Over %d CVEs affect these protocols, highest CVSS: %.1f", desc, len(cves), getHighestCVSS(cves))
			// Keep only the highest scoring CVEs
			cves = getTopCVEs(cves, 5)
		}
		
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "Deprecated TLS Versions",
			Severity:    "MEDIUM",
			Description: desc,
			Affected:    true,
			CVEs:        cves,
		})
	}
	
	// No Forward Secrecy
	hasForwardSecrecy := false
	for _, cipher := range result.CipherSuites {
		if cipher.Forward {
			hasForwardSecrecy = true
			break
		}
	}
	
	if !hasForwardSecrecy && len(result.CipherSuites) > 0 {
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "No Forward Secrecy",
			Severity:    "LOW",
			Description: "No cipher suites support forward secrecy - past sessions could be decrypted if private key is compromised in the future",
			Affected:    true,
			// No CVE - this is a cryptographic property, not a vulnerability
		})
	}
	
	// Heartbleed (CVE-2014-0160) - Heuristic detection
	heartbleedInfo := s.checkHeartbleedHeuristic(result)
	if heartbleedInfo.Affected {
		vulns = append(vulns, heartbleedInfo)
	}
	
	return vulns
}

// checkHeartbleedHeuristic performs heuristic detection for Heartbleed vulnerability
// Note: This is NOT an active exploitation test, but a heuristic check based on:
// - TLS version (only TLS 1.0-1.2 are affected)
// - Server behavior and cipher preferences
// - Known patterns from patched vs unpatched servers
func (s *Scanner) checkHeartbleedHeuristic(result *Result) VulnerabilityInfo {
	info := VulnerabilityInfo{
		Name:        "Heartbleed",
		Severity:    "CRITICAL",
		Description: "Heartbleed (CVE-2014-0160) vulnerability detected based on heuristic analysis",
		Affected:    false,
		CVEs: []CVEInfo{
			{ID: "CVE-2014-0160", CVSS: 7.5},
		},
	}
	
	// Check 1: TLS version - Heartbleed only affects TLS 1.0, 1.1, and 1.2
	vulnerableVersionFound := false
	var vulnerableVersions []string
	
	for _, proto := range result.SupportedProtocols {
		if proto.Enabled {
			switch proto.Version {
			case ztls.VersionTLS10, ztls.VersionTLS11, ztls.VersionTLS12:
				vulnerableVersionFound = true
				vulnerableVersions = append(vulnerableVersions, proto.Name)
			}
		}
	}
	
	// If only TLS 1.3 is supported, server is not vulnerable
	if !vulnerableVersionFound {
		return info
	}
	
	// Check 2: Analyze cipher suite preferences
	// Servers patched post-Heartbleed often updated their cipher preferences
	hasModernCiphers := false
	hasLegacyCiphers := false
	
	for _, cipher := range result.CipherSuites {
		// Modern ciphers (typically added/preferred post-2014)
		if strings.Contains(cipher.Name, "CHACHA20") || 
		   strings.Contains(cipher.Name, "AES_256_GCM") {
			hasModernCiphers = true
		}
		
		// Legacy ciphers often indicate older, potentially unpatched servers
		if strings.Contains(cipher.Name, "RC4") || 
		   strings.Contains(cipher.Name, "3DES") ||
		   strings.Contains(cipher.Name, "DES_CBC") {
			hasLegacyCiphers = true
		}
	}
	
	// Check 3: Certificate age can be an indicator
	certIsOld := false
	if result.Certificate != nil && !result.Certificate.NotBefore.IsZero() {
		// If certificate was issued before April 2014 (Heartbleed disclosure)
		// and hasn't been reissued, it's more likely the server is unpatched
		heartbleedDate := time.Date(2014, 4, 7, 0, 0, 0, 0, time.UTC)
		if result.Certificate.NotBefore.Before(heartbleedDate) {
			certIsOld = true
		}
	}
	
	// Calculate confidence score based on multiple factors
	confidenceScore := 0
	var indicators []string
	
	if vulnerableVersionFound {
		confidenceScore += 40
		indicators = append(indicators, fmt.Sprintf("Supports vulnerable TLS versions: %s", strings.Join(vulnerableVersions, ", ")))
	}
	
	if hasLegacyCiphers && !hasModernCiphers {
		confidenceScore += 30
		indicators = append(indicators, "Uses only legacy cipher suites")
	} else if hasLegacyCiphers {
		confidenceScore += 15
		indicators = append(indicators, "Supports legacy cipher suites")
	}
	
	if certIsOld {
		confidenceScore += 20
		indicators = append(indicators, "Certificate issued before Heartbleed disclosure")
	}
	
	// Check 4: Analyze server behavior patterns
	// Servers that were emergency-patched often have specific cipher ordering
	if len(result.CipherSuites) > 0 {
		firstCipher := result.CipherSuites[0].Name
		// Many emergency patches defaulted to specific cipher preferences
		if strings.Contains(firstCipher, "ECDHE_RSA_WITH_AES_128_CBC_SHA") ||
		   strings.Contains(firstCipher, "DHE_RSA_WITH_AES_128_CBC_SHA") {
			confidenceScore += 10
			indicators = append(indicators, "Cipher preference matches common emergency patch patterns")
		}
	}
	
	// Debug output for Heartbleed detection
	if s.config.Verbose {
		fmt.Printf("DEBUG Heartbleed: Score=%d, HasLegacy=%v, HasModern=%v, CertOld=%v\n", 
			confidenceScore, hasLegacyCiphers, hasModernCiphers, certIsOld)
	}
	
	// Determine if we should flag as potentially vulnerable
	if confidenceScore >= 60 {
		info.Affected = true
		info.Description = fmt.Sprintf(
			"Heartbleed vulnerability suspected (confidence: %d%%) based on heuristic analysis. "+
			"This is NOT an active exploitation test. Indicators: %s. "+
			"Recommend immediate verification with dedicated Heartbleed testing tools.",
			confidenceScore,
			strings.Join(indicators, "; "),
		)
		
		// Adjust severity based on confidence
		if confidenceScore >= 80 {
			info.Severity = "CRITICAL"
		} else if confidenceScore >= 60 {
			info.Severity = "HIGH"
		}
	}
	
	return info
}

// getHighestCVSS returns the highest CVSS score from a list of CVEs
func getHighestCVSS(cves []CVEInfo) float64 {
	highest := 0.0
	for _, cve := range cves {
		if cve.CVSS > highest {
			highest = cve.CVSS
		}
	}
	return highest
}

// getTopCVEs returns the top N CVEs by CVSS score
func getTopCVEs(cves []CVEInfo, n int) []CVEInfo {
	// Simple sort by CVSS score (descending)
	for i := 0; i < len(cves); i++ {
		for j := i + 1; j < len(cves); j++ {
			if cves[j].CVSS > cves[i].CVSS {
				cves[i], cves[j] = cves[j], cves[i]
			}
		}
	}
	
	if len(cves) <= n {
		return cves
	}
	return cves[:n]
}

func parseTarget(target string) (host, port string, err error) {
	// Handle various input formats
	if !strings.Contains(target, ":") {
		return target, "443", nil
	}
	
	host, port, err = net.SplitHostPort(target)
	if err != nil {
		return "", "", err
	}
	
	return host, port, nil
}

func getCipherName(id uint16) string {
	// Map cipher IDs to names
	for _, suite := range ztls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	for _, suite := range ztls.InsecureCipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	return fmt.Sprintf("Unknown (0x%04x)", id)
}

func evaluateCipherStrength(name string) string {
	switch {
	// NULL ciphers - no encryption at all
	case strings.Contains(name, "NULL"):
		return "NULL_CIPHER"
	// Export ciphers - 40-bit or 56-bit encryption
	case strings.Contains(name, "EXPORT") || strings.Contains(name, "_40_") || strings.Contains(name, "DES40"):
		return "EXPORT"
	// Anonymous ciphers - no authentication
	case strings.Contains(name, "_anon_") || strings.Contains(name, "DH_anon") || strings.Contains(name, "ECDH_anon") || strings.Contains(name, "ADH"):
		return "ANONYMOUS"
	// Broken ciphers
	case strings.Contains(name, "RC4") || strings.Contains(name, "RC2") || strings.Contains(name, "IDEA"):
		return "BROKEN"
	// Single DES (56-bit)
	case strings.Contains(name, "DES_CBC") && !strings.Contains(name, "3DES"):
		return "WEAK"
	// 3DES
	case strings.Contains(name, "3DES"):
		return "MEDIUM"
	// Strong ciphers
	case strings.Contains(name, "AES_128_GCM") || strings.Contains(name, "CHACHA20"):
		return "STRONG"
	case strings.Contains(name, "AES_256_GCM"):
		return "VERY_STRONG"
	default:
		return "MEDIUM"
	}
}

func hasForwardSecrecy(name string) bool {
	// TLS 1.3 cipher suites always have forward secrecy
	if strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_") {
		return true
	}
	// TLS 1.2 and below need ECDHE or DHE for forward secrecy
	return strings.Contains(name, "ECDHE") || strings.Contains(name, "DHE")
}

func isAEADCipher(name string) bool {
	return strings.Contains(name, "GCM") || strings.Contains(name, "POLY1305") || strings.Contains(name, "CCM")
}

func calculateGrades(result *Result) {
	// First calculate SSL Labs scores
	calculateSSLLabsScore(result)
	
	// Then calculate our subcategory grades
	calculateSubcategoryGrades(result)
}

func calculateSSLLabsScore(result *Result) {
	// Initialize degradations slice
	result.GradeDegradations = []GradeDegradation{}
	
	// SSL Labs scoring based on their methodology
	// 1. Protocol Support (30% weight)
	protocolScore := calculateProtocolScore(result)
	result.ProtocolSupportScore = protocolScore
	identifyProtocolDegradations(result)
	
	// 2. Key Exchange (30% weight) 
	keyExchangeScore := calculateKeyExchangeScore(result)
	result.KeyExchangeScore = keyExchangeScore
	identifyKeyExchangeDegradations(result)
	
	// 3. Cipher Strength (40% weight)
	cipherScore := calculateCipherStrengthScore(result)
	result.CipherStrengthScore = cipherScore
	identifyCipherDegradations(result)
	
	// Calculate overall score using SSL Labs weights
	overallScore := float64(protocolScore)*0.3 + 
	                float64(keyExchangeScore)*0.3 + 
	                float64(cipherScore)*0.4
	result.Score = int(overallScore)
	
	// Check for automatic failures (SSL Labs rules)
	if hasCertificateFailure(result) {
		// Check specifically for hostname mismatch
		if hasHostnameMismatch(result) {
			result.Grade = "M"
			// Keep the calculated score instead of zeroing it
		} else {
			result.Grade = "F"
			result.Score = 0
		}
		identifyCertificateDegradations(result)
		return
	}
	
	// Convert score to grade
	result.Grade = sslLabsScoreToGrade(result.Score)
	
	// Apply SSL Labs grade capping rules
	result.Grade = applyGradeCaps(result)
}

func applyGradeCaps(result *Result) string {
	currentGrade := result.Grade
	maxGrade := "A+"
	
	// Check for 3DES - caps at B
	for _, cipher := range result.CipherSuites {
		if strings.Contains(cipher.Name, "3DES") {
			maxGrade = minGrade(maxGrade, "B")
			result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
				Category:    "cipher",
				Issue:       "3DES cipher suite support",
				Details:     "3DES is obsolete and caps grade at B",
				Impact:      "Grade capped at B maximum",
				Remediation: "Remove all 3DES cipher suites",
			})
			break
		}
	}
	
	// Check for RC4 - caps at F
	for _, cipher := range result.CipherSuites {
		if strings.Contains(cipher.Name, "RC4") {
			maxGrade = "F"
			result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
				Category:    "cipher",
				Issue:       "RC4 cipher suite support",
				Details:     "RC4 is broken and results in automatic F",
				Impact:      "Automatic F grade",
				Remediation: "Remove all RC4 cipher suites immediately",
			})
			break
		}
	}
	
	// Check for TLS 1.0 - caps at C (SSL Labs policy)
	for _, proto := range result.SupportedProtocols {
		if proto.Enabled && proto.Version == ztls.VersionTLS10 {
			maxGrade = minGrade(maxGrade, "C")
			break
		}
	}
	
	// Check for no PFS at all - caps at B
	hasPFS := false
	for _, cipher := range result.CipherSuites {
		if cipher.Forward {
			hasPFS = true
			break
		}
	}
	if !hasPFS && len(result.CipherSuites) > 0 {
		maxGrade = minGrade(maxGrade, "B")
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "key_exchange",
			Issue:       "No forward secrecy support",
			Details:     "No cipher suites support forward secrecy",
			Impact:      "Grade capped at B maximum",
			Remediation: "Enable ECDHE or DHE cipher suites",
		})
	}
	
	// Return the lower of current grade or max allowed grade
	return minGrade(currentGrade, maxGrade)
}

func minGrade(a, b string) string {
	// Grade order: A+ > A > B > C > D > E > F
	gradeOrder := map[string]int{
		"A+": 7,
		"A":  6,
		"B":  5,
		"C":  4,
		"D":  3,
		"E":  2,
		"F":  1,
	}
	
	aVal, aOk := gradeOrder[a]
	bVal, bOk := gradeOrder[b]
	
	if !aOk {
		return b
	}
	if !bOk {
		return a
	}
	
	if aVal < bVal {
		return a
	}
	return b
}

func calculateProtocolScore(result *Result) int {
	if len(result.SupportedProtocols) == 0 {
		return 0
	}
	
	// SSL Labs protocol scoring - updated to match real SSL Labs
	protocolScores := map[uint16]int{
		ztls.VersionSSL30: 0,   // SSL 3.0 - Automatic F
		ztls.VersionTLS10: 20,  // TLS 1.0 - Deprecated
		ztls.VersionTLS11: 40,  // TLS 1.1 - Deprecated  
		ztls.VersionTLS12: 95,  // TLS 1.2
		ztls.VersionTLS13: 100, // TLS 1.3
	}
	
	best := 0
	worst := 100
	
	for _, proto := range result.SupportedProtocols {
		if proto.Enabled {
			score, ok := protocolScores[proto.Version]
			if !ok {
				score = 0
			}
			if score > best {
				best = score
			}
			if score < worst {
				worst = score
			}
		}
	}
	
	// SSL Labs formula: (best + worst) / 2
	return (best + worst) / 2
}

func calculateKeyExchangeScore(result *Result) int {
	if len(result.CipherSuites) == 0 {
		return 0
	}
	
	best := 0
	worst := 100
	
	for _, cipher := range result.CipherSuites {
		score := 0
		
		// Score based on key exchange algorithm
		if strings.Contains(cipher.Name, "ECDHE") {
			score = 100 // ECDHE is best
		} else if strings.Contains(cipher.Name, "DHE") {
			score = 90  // DHE is good
		} else if strings.Contains(cipher.Name, "RSA") {
			score = 60  // RSA key exchange (no forward secrecy)
		} else if strings.Contains(cipher.Name, "anon") {
			score = 0   // Anonymous key exchange
		} else {
			score = 50  // Unknown/other
		}
		
		if score > best {
			best = score
		}
		if score < worst {
			worst = score
		}
	}
	
	return (best + worst) / 2
}

func calculateCipherStrengthScore(result *Result) int {
	if len(result.CipherSuites) == 0 {
		return 0
	}
	
	best := 0
	worst := 100
	
	for _, cipher := range result.CipherSuites {
		score := getCipherStrengthScore(cipher.Name)
		
		if score > best {
			best = score
		}
		if score < worst {
			worst = score
		}
	}
	
	return (best + worst) / 2
}

func getCipherStrengthScore(cipherName string) int {
	// SSL Labs cipher strength scoring
	switch {
	// Null cipher
	case strings.Contains(cipherName, "NULL"):
		return 0
		
	// Export ciphers
	case strings.Contains(cipherName, "EXPORT"):
		return 0
		
	// DES/RC4
	case strings.Contains(cipherName, "DES") && !strings.Contains(cipherName, "3DES"):
		return 20
	case strings.Contains(cipherName, "RC4"):
		return 20
		
	// 3DES
	case strings.Contains(cipherName, "3DES"):
		return 50
		
	// 128-bit ciphers
	case strings.Contains(cipherName, "AES_128") || strings.Contains(cipherName, "AES128"):
		if strings.Contains(cipherName, "GCM") {
			return 90
		}
		return 80
		
	// CHACHA20
	case strings.Contains(cipherName, "CHACHA20"):
		return 90
		
	// 256-bit ciphers
	case strings.Contains(cipherName, "AES_256") || strings.Contains(cipherName, "AES256"):
		if strings.Contains(cipherName, "GCM") {
			return 100
		}
		return 90
		
	default:
		return 40
	}
}

func hasCertificateFailure(result *Result) bool {
	if result.Certificate == nil {
		return true
	}
	
	// SSL Labs automatic F grade conditions
	if !result.Certificate.IsValid {
		return true
	}
	
	// Check for specific failures (excluding hostname mismatch)
	for _, err := range result.Certificate.ValidationErrors {
		if strings.Contains(err, "expired") ||
		   strings.Contains(err, "self-signed") {
			return true
		}
	}
	
	// Check for weak signature algorithms
	if strings.Contains(result.Certificate.SignatureAlgorithm, "MD5") ||
	   strings.Contains(result.Certificate.SignatureAlgorithm, "SHA1") {
		return true
	}
	
	return false
}

func hasHostnameMismatch(result *Result) bool {
	if result.Certificate == nil {
		return false
	}
	
	for _, err := range result.Certificate.ValidationErrors {
		if strings.Contains(err, "Hostname verification failed") {
			return true
		}
	}
	
	return false
}

func sslLabsScoreToGrade(score int) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 65:
		return "B"
	case score >= 50:
		return "C"
	case score >= 35:
		return "D"
	case score >= 20:
		return "E"
	default:
		return "F"
	}
}

func calculateSubcategoryGrades(result *Result) {
	// Calculate our detailed protocol/cipher grade
	protocolScore := 100
	
	// Deduct points for weak protocols
	for _, proto := range result.SupportedProtocols {
		if proto.Enabled {
			switch proto.Version {
			case ztls.VersionSSL30:
				protocolScore = 0  // Auto-fail for SSL 3.0
			case ztls.VersionTLS10:
				protocolScore -= 20
			case ztls.VersionTLS11:
				protocolScore -= 10
			}
		}
	}
	
	// Deduct for weak ciphers
	for _, cipher := range result.CipherSuites {
		switch cipher.Strength {
		case "INSECURE":
			protocolScore -= 30
		case "WEAK":
			protocolScore -= 20
		case "MEDIUM":
			protocolScore -= 5
		}
	}
	
	// Check for best practices
	hasForwardSecrecy := false
	for _, cipher := range result.CipherSuites {
		if cipher.Forward {
			hasForwardSecrecy = true
			break
		}
	}
	
	// Bonus points for best practices
	if !hasForwardSecrecy && len(result.CipherSuites) > 0 {
		protocolScore -= 10 // Penalty for no forward secrecy
	}
	
	// Ensure score doesn't go below 0
	if protocolScore < 0 {
		protocolScore = 0
	}
	
	result.ProtocolScore = protocolScore
	result.ProtocolGrade = scoreToGrade(protocolScore)
	
	// Calculate Certificate grade
	certScore := 100
	
	if result.Certificate != nil {
		// Track individual issues to avoid double-counting
		hasExpired := false
		hasHostnameMismatch := false
		isSelfSigned := result.Certificate.Subject == result.Certificate.Issuer
		
		// Check for specific issues
		for _, err := range result.Certificate.ValidationErrors {
			if strings.Contains(err, "expired") {
				hasExpired = true
			} else if strings.Contains(err, "not yet valid") {
				hasExpired = true
			} else if strings.Contains(err, "Hostname verification failed") {
				hasHostnameMismatch = true
			}
		}
		
		// Apply penalties (don't double-count IsValid flag)
		if hasExpired {
			certScore -= 40 // Expired cert is serious
		}
		
		if hasHostnameMismatch {
			certScore -= 30 // Expected when scanning by IP
		}
		
		if isSelfSigned {
			certScore -= 20 // Common for internal services
		}
		
		// Check signature algorithm
		if strings.Contains(result.Certificate.SignatureAlgorithm, "SHA1") {
			certScore -= 20
		} else if strings.Contains(result.Certificate.SignatureAlgorithm, "MD5") {
			certScore -= 50 // MD5 is broken
		}
		
		// Chain validation issues (if not already counted above)
		if !result.Certificate.IsValid && !hasExpired && !hasHostnameMismatch && !isSelfSigned {
			certScore -= 30 // Other validation issues
		}
	} else {
		certScore = 0 // No certificate
	}
	
	// Ensure score doesn't go below 0
	if certScore < 0 {
		certScore = 0
	}
	
	result.CertificateScore = certScore
	result.CertificateGrade = scoreToGrade(certScore)
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

func identifyProtocolDegradations(result *Result) {
	var weakProtocols []string
	
	for _, proto := range result.SupportedProtocols {
		if proto.Enabled {
			switch proto.Version {
			case ztls.VersionSSL30:
				weakProtocols = append(weakProtocols, proto.Name)
			case ztls.VersionTLS10:
				weakProtocols = append(weakProtocols, proto.Name)
			case ztls.VersionTLS11:
				weakProtocols = append(weakProtocols, proto.Name)
			}
		}
	}
	
	if len(weakProtocols) > 0 {
		impact := fmt.Sprintf("Reduces Protocol Support score to %d/100", result.ProtocolSupportScore)
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "protocol",
			Issue:       "Weak protocols enabled",
			Details:     strings.Join(weakProtocols, ", "),
			Impact:      impact,
			Remediation: "Disable TLS 1.1 and below. Only enable TLS 1.2 and TLS 1.3.",
		})
	}
}

func identifyKeyExchangeDegradations(result *Result) {
	var nonPFSCiphers []string
	var anonCiphers []string
	
	for _, cipher := range result.CipherSuites {
		if !cipher.Forward {
			if strings.Contains(cipher.Name, "anon") {
				anonCiphers = append(anonCiphers, cipher.Name)
			} else {
				nonPFSCiphers = append(nonPFSCiphers, cipher.Name)
			}
		}
	}
	
	if len(anonCiphers) > 0 {
		impact := fmt.Sprintf("Severely reduces Key Exchange score to %d/100", result.KeyExchangeScore)
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "key_exchange",
			Issue:       "Anonymous key exchange ciphers",
			Details:     strings.Join(anonCiphers, ", "),
			Impact:      impact,
			Remediation: "Remove all anonymous cipher suites immediately.",
		})
	}
	
	if len(nonPFSCiphers) > 0 {
		impact := fmt.Sprintf("Reduces Key Exchange score to %d/100", result.KeyExchangeScore)
		details := strings.Join(nonPFSCiphers, ", ")
		if len(nonPFSCiphers) > 3 {
			details = fmt.Sprintf("%d cipher suites without forward secrecy (e.g., %s)", 
				len(nonPFSCiphers), nonPFSCiphers[0])
		}
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "key_exchange",
			Issue:       "Cipher suites without forward secrecy",
			Details:     details,
			Impact:      impact,
			Remediation: "Use only ECDHE or DHE cipher suites for forward secrecy.",
		})
	}
}

func identifyCipherDegradations(result *Result) {
	var weakCiphers []string
	var nullCiphers []string
	var exportCiphers []string
	
	for _, cipher := range result.CipherSuites {
		score := getCipherStrengthScore(cipher.Name)
		if score == 0 {
			if strings.Contains(cipher.Name, "NULL") {
				nullCiphers = append(nullCiphers, cipher.Name)
			} else if strings.Contains(cipher.Name, "EXPORT") {
				exportCiphers = append(exportCiphers, cipher.Name)
			}
		} else if score <= 50 {
			weakCiphers = append(weakCiphers, cipher.Name)
		}
	}
	
	if len(nullCiphers) > 0 || len(exportCiphers) > 0 {
		allBad := append(nullCiphers, exportCiphers...)
		impact := fmt.Sprintf("Severely reduces Cipher Strength score to %d/100", result.CipherStrengthScore)
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "cipher",
			Issue:       "Extremely weak or null ciphers",
			Details:     strings.Join(allBad, ", "),
			Impact:      impact,
			Remediation: "Remove NULL and EXPORT cipher suites immediately.",
		})
	}
	
	if len(weakCiphers) > 0 {
		impact := fmt.Sprintf("Reduces Cipher Strength score to %d/100", result.CipherStrengthScore)
		details := strings.Join(weakCiphers, ", ")
		if len(weakCiphers) > 3 {
			details = fmt.Sprintf("%d weak cipher suites (e.g., %s)", len(weakCiphers), weakCiphers[0])
		}
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "cipher",
			Issue:       "Weak cipher suites enabled",
			Details:     details,
			Impact:      impact,
			Remediation: "Use AES-GCM or ChaCha20-Poly1305 ciphers. Avoid 3DES, RC4, and DES.",
		})
	}
}

func identifyCertificateDegradations(result *Result) {
	if result.Certificate == nil {
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "certificate",
			Issue:       "No certificate found",
			Details:     "Unable to retrieve certificate",
			Impact:      "Automatic F grade",
			Remediation: "Ensure TLS is properly configured with a valid certificate.",
		})
		return
	}
	
	// Check each type of certificate issue
	for _, err := range result.Certificate.ValidationErrors {
		if strings.Contains(err, "expired") {
			result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
				Category:    "certificate",
				Issue:       "Certificate expired",
				Details:     fmt.Sprintf("Expired on %s", result.Certificate.NotAfter.Format("2006-01-02")),
				Impact:      "Automatic F grade",
				Remediation: "Renew the certificate immediately.",
			})
		} else if strings.Contains(err, "Hostname verification failed") {
			result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
				Category:    "certificate",
				Issue:       "Hostname mismatch",
				Details:     err,
				Impact:      "Grade: M (Mismatch)",
				Remediation: "Use a certificate with the correct hostname or SAN entries.",
			})
		}
	}
	
	if result.Certificate.Subject == result.Certificate.Issuer {
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "certificate",
			Issue:       "Self-signed certificate",
			Details:     "Certificate is self-signed",
			Impact:      "Automatic F grade",
			Remediation: "Use a certificate from a trusted Certificate Authority.",
		})
	}
	
	if strings.Contains(result.Certificate.SignatureAlgorithm, "SHA1") {
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "certificate",
			Issue:       "Weak signature algorithm",
			Details:     result.Certificate.SignatureAlgorithm,
			Impact:      "Automatic F grade",
			Remediation: "Use SHA-256 or stronger signature algorithm.",
		})
	} else if strings.Contains(result.Certificate.SignatureAlgorithm, "MD5") {
		result.GradeDegradations = append(result.GradeDegradations, GradeDegradation{
			Category:    "certificate",
			Issue:       "Broken signature algorithm",
			Details:     result.Certificate.SignatureAlgorithm,
			Impact:      "Automatic F grade",
			Remediation: "MD5 is cryptographically broken. Use SHA-256 or stronger.",
		})
	}
}