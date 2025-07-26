package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
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
}

type Result struct {
	Target             string              `json:"target"`
	IP                 string              `json:"ip"`
	Port               string              `json:"port"`
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
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Affected    bool   `json:"affected"`
}

func New(config Config) *Scanner {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 10
	}
	return &Scanner{config: config}
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
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		// TCP works but TLS doesn't - still - grade
		result.Errors = append(result.Errors, fmt.Sprintf("TLS handshake failed: %v", err))
		result.Grade = "-"
		result.Score = 0
		result.Duration = time.Since(start)
		return result, nil
	}
	tlsConn.Close()

	// Test protocols
	// Note: Go's crypto/tls doesn't support SSL v2, and SSL v3 support was removed in Go 1.14+
	// This means we cannot detect if a server supports these ancient protocols
	protocols := []struct {
		name    string
		version uint16
	}{
		{"SSL 3.0", tls.VersionSSL30}, // Won't actually work in modern Go
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
		{"TLS 1.3", tls.VersionTLS13},
	}

	for _, proto := range protocols {
		info := ProtocolInfo{
			Name:    proto.name,
			Version: proto.version,
		}
		
		if s.testProtocol(host, port, proto.version) {
			info.Enabled = true
			result.SupportedProtocols = append(result.SupportedProtocols, info)
			
			// Get ciphers for this protocol
			ciphers := s.getCiphersForProtocol(host, port, proto.version, proto.name)
			result.CipherSuites = append(result.CipherSuites, ciphers...)
		}
	}

	// Get certificate info
	certInfo, err := s.getCertificateInfo(host, port)
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

func (s *Scanner) testProtocol(host, port string, version uint16) bool {
	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}
	
	target := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	})
	
	if err != nil {
		return false
	}
	defer conn.Close()
	
	return true
}

func (s *Scanner) getCiphersForProtocol(host, port string, version uint16, protoName string) []CipherInfo {
	var ciphers []CipherInfo
	
	// Get appropriate cipher suites for the protocol version
	var testCiphers []uint16
	for _, suite := range tls.CipherSuites() {
		if version == tls.VersionTLS13 {
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
	for _, suite := range tls.InsecureCipherSuites() {
		if version != tls.VersionTLS13 {
			testCiphers = append(testCiphers, suite.ID)
		}
	}
	
	target := net.JoinHostPort(host, port)
	
	for _, cipherID := range testCiphers {
		dialer := &net.Dialer{
			Timeout: s.config.Timeout,
		}
		
		conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			CipherSuites:       []uint16{cipherID},
			InsecureSkipVerify: true,
		})
		
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

func (s *Scanner) getCertificateInfo(host, port string) (*CertificateInfo, error) {
	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}
	
	target := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})
	
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
	
	// Validation
	now := time.Now()
	if now.Before(cert.NotBefore) {
		info.IsValid = false
		info.ValidationErrors = append(info.ValidationErrors, "Certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		info.IsValid = false
		info.ValidationErrors = append(info.ValidationErrors, "Certificate expired")
	}
	
	// Check hostname
	if err := cert.VerifyHostname(host); err != nil {
		info.IsValid = false
		info.ValidationErrors = append(info.ValidationErrors, fmt.Sprintf("Hostname verification failed: %v", err))
	}
	
	return info, nil
}

func (s *Scanner) checkVulnerabilities(host, port string, result *Result) []VulnerabilityInfo {
	vulns := []VulnerabilityInfo{}
	
	// Check for weak protocols
	for _, proto := range result.SupportedProtocols {
		if proto.Version < tls.VersionTLS12 && proto.Enabled {
			vulns = append(vulns, VulnerabilityInfo{
				Name:        fmt.Sprintf("%s Support", proto.Name),
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Server supports %s which is considered weak", proto.Name),
				Affected:    true,
			})
		}
	}
	
	// Check for weak ciphers
	weakCipherCount := 0
	for _, cipher := range result.CipherSuites {
		if cipher.Strength == "WEAK" || cipher.Strength == "INSECURE" {
			weakCipherCount++
		}
	}
	
	if weakCipherCount > 0 {
		vulns = append(vulns, VulnerabilityInfo{
			Name:        "Weak Ciphers",
			Severity:    "HIGH",
			Description: fmt.Sprintf("Server supports %d weak cipher suites", weakCipherCount),
			Affected:    true,
		})
	}
	
	// More vulnerability checks would go here (Heartbleed, POODLE, etc.)
	
	return vulns
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
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	return fmt.Sprintf("Unknown (0x%04x)", id)
}

func evaluateCipherStrength(name string) string {
	switch {
	case strings.Contains(name, "NULL") || strings.Contains(name, "anon") || strings.Contains(name, "EXPORT"):
		return "INSECURE"
	case strings.Contains(name, "RC4") || strings.Contains(name, "DES") && !strings.Contains(name, "3DES"):
		return "WEAK"
	case strings.Contains(name, "3DES"):
		return "MEDIUM"
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
		if proto.Enabled && proto.Version == tls.VersionTLS10 {
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
		tls.VersionSSL30: 0,   // SSL 3.0 - Automatic F
		tls.VersionTLS10: 20,  // TLS 1.0 - Deprecated
		tls.VersionTLS11: 40,  // TLS 1.1 - Deprecated  
		tls.VersionTLS12: 95,  // TLS 1.2
		tls.VersionTLS13: 100, // TLS 1.3
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
			case tls.VersionSSL30:
				protocolScore = 0  // Auto-fail for SSL 3.0
			case tls.VersionTLS10:
				protocolScore -= 20
			case tls.VersionTLS11:
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
			case tls.VersionSSL30:
				weakProtocols = append(weakProtocols, proto.Name)
			case tls.VersionTLS10:
				weakProtocols = append(weakProtocols, proto.Name)
			case tls.VersionTLS11:
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