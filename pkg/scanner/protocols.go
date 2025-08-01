package scanner

// ProtocolType represents how to connect to the service
type ProtocolType int

const (
	ProtocolTLS ProtocolType = iota
	ProtocolSTARTTLS
)

// ServiceInfo contains information about a network service
type ServiceInfo struct {
	Name         string
	Protocol     ProtocolType
	STARTTLSType string // "smtp", "imap", "pop3", "ldap", "postgresql", "mysql"
}

// Well-known port to service mapping
var portServiceMap = map[string]ServiceInfo{
	// SMTP
	"25":  {Name: "SMTP", Protocol: ProtocolSTARTTLS, STARTTLSType: "smtp"},
	"587": {Name: "SMTP Submission", Protocol: ProtocolSTARTTLS, STARTTLSType: "smtp"},
	"465": {Name: "SMTPS", Protocol: ProtocolTLS},
	
	// IMAP
	"143": {Name: "IMAP", Protocol: ProtocolSTARTTLS, STARTTLSType: "imap"},
	"993": {Name: "IMAPS", Protocol: ProtocolTLS},
	
	// POP3
	"110": {Name: "POP3", Protocol: ProtocolSTARTTLS, STARTTLSType: "pop3"},
	"995": {Name: "POP3S", Protocol: ProtocolTLS},
	
	// FTP
	"21":  {Name: "FTP", Protocol: ProtocolSTARTTLS, STARTTLSType: "ftp"},
	
	// LDAP
	"389": {Name: "LDAP", Protocol: ProtocolSTARTTLS, STARTTLSType: "ldap"},
	"636": {Name: "LDAPS", Protocol: ProtocolTLS},
	
	// Databases
	"5432": {Name: "PostgreSQL", Protocol: ProtocolSTARTTLS, STARTTLSType: "postgresql"},
	"3306": {Name: "MySQL", Protocol: ProtocolSTARTTLS, STARTTLSType: "mysql"},
	
	// Web
	"443":  {Name: "HTTPS", Protocol: ProtocolTLS},
	"8443": {Name: "HTTPS-Alt", Protocol: ProtocolTLS},
	"8080": {Name: "HTTP-Alt", Protocol: ProtocolTLS}, // Often HTTPS on 8080
	
	// Other common TLS ports
	"22":   {Name: "SSH", Protocol: ProtocolTLS},
	"990":  {Name: "FTPS", Protocol: ProtocolTLS},
	"5061": {Name: "SIPS", Protocol: ProtocolTLS},
}

// DetectServiceType determines the service type based on port
func DetectServiceType(port string) ServiceInfo {
	if service, ok := portServiceMap[port]; ok {
		return service
	}
	
	// Default to direct TLS for unknown ports
	return ServiceInfo{
		Name:     "Unknown",
		Protocol: ProtocolTLS,
	}
}

// ProbeUnknownPort attempts to detect the protocol on an unknown port
func ProbeUnknownPort(host, port string) ServiceInfo {
	// For now, default to TLS
	// TODO: Implement actual probing logic
	// 1. Try direct TLS connection
	// 2. If that fails, try common STARTTLS protocols
	// 3. Look for protocol-specific banners
	
	return ServiceInfo{
		Name:     "Unknown",
		Protocol: ProtocolTLS,
	}
}