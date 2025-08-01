//nolint:err113 // This file uses dynamic errors to provide detailed STARTTLS negotiation feedback
package scanner

import (
	"bufio"
	ztls "github.com/zmap/zcrypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// StartTLSNegotiator handles STARTTLS negotiation for different protocols
type StartTLSNegotiator interface {
	Negotiate(conn net.Conn) error
}

// SMTPStartTLS handles SMTP STARTTLS negotiation
type SMTPStartTLS struct{}

func (s *SMTPStartTLS) Negotiate(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	
	// Read greeting
	_, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read SMTP greeting: %w", err)
	}
	
	// Send EHLO
	_, err = conn.Write([]byte("EHLO localhost\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send EHLO: %w", err)
	}
	
	// Read EHLO response and check for STARTTLS
	supportsStartTLS := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read EHLO response: %w", err)
		}
		
		// Check for STARTTLS support
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			supportsStartTLS = true
		}
		
		// Check if this is the last line (starts with 250 space)
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	
	if !supportsStartTLS {
		return fmt.Errorf("server does not support STARTTLS")
	}
	
	// Send STARTTLS command
	_, err = conn.Write([]byte("STARTTLS\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send STARTTLS: %w", err)
	}
	
	// Read STARTTLS response
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read STARTTLS response: %w", err)
	}
	
	if !strings.HasPrefix(response, "220") {
		return fmt.Errorf("STARTTLS failed: %s", strings.TrimSpace(response))
	}
	
	return nil // Success
}

// IMAPStartTLS handles IMAP STARTTLS negotiation
type IMAPStartTLS struct{}

func (i *IMAPStartTLS) Negotiate(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	
	// Read greeting
	_, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read IMAP greeting: %w", err)
	}
	
	// Send CAPABILITY command
	_, err = conn.Write([]byte("a001 CAPABILITY\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send CAPABILITY: %w", err)
	}
	
	// Read CAPABILITY response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read CAPABILITY response: %w", err)
		}
		
		if strings.Contains(strings.ToUpper(line), "STARTTLS") {
			// Send STARTTLS command
			_, err = conn.Write([]byte("a002 STARTTLS\r\n"))
			if err != nil {
				return fmt.Errorf("failed to send STARTTLS: %w", err)
			}
			
			// Read STARTTLS response
			response, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read STARTTLS response: %w", err)
			}
			
			if !strings.Contains(response, "OK") {
				return fmt.Errorf("STARTTLS failed: %s", response)
			}
			
			return nil // Success
		}
		
		// Check if this is the last line
		if strings.HasPrefix(line, "a001 OK") {
			break
		}
	}
	
	return fmt.Errorf("server does not support STARTTLS")
}

// POP3StartTLS handles POP3 STARTTLS negotiation
type POP3StartTLS struct{}

func (p *POP3StartTLS) Negotiate(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	
	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read POP3 greeting: %w", err)
	}
	
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("invalid POP3 greeting: %s", greeting)
	}
	
	// Send CAPA command
	_, err = conn.Write([]byte("CAPA\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send CAPA: %w", err)
	}
	
	// Read CAPA response
	hasSTLS := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read CAPA response: %w", err)
		}
		
		if strings.TrimSpace(line) == "." {
			break
		}
		
		if strings.ToUpper(strings.TrimSpace(line)) == "STLS" {
			hasSTLS = true
		}
	}
	
	if !hasSTLS {
		return fmt.Errorf("server does not support STLS")
	}
	
	// Send STLS command
	_, err = conn.Write([]byte("STLS\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send STLS: %w", err)
	}
	
	// Read STLS response
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read STLS response: %w", err)
	}
	
	if !strings.HasPrefix(response, "+OK") {
		return fmt.Errorf("STLS failed: %s", response)
	}
	
	return nil // Success
}

// FTPStartTLS handles FTP AUTH TLS negotiation
type FTPStartTLS struct{}

func (f *FTPStartTLS) Negotiate(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	
	// Read greeting (220 response)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read FTP greeting: %w", err)
	}
	
	if !strings.HasPrefix(greeting, "220") {
		return fmt.Errorf("unexpected FTP greeting: %s", greeting)
	}
	
	// Send AUTH TLS command
	_, err = conn.Write([]byte("AUTH TLS\r\n"))
	if err != nil {
		return fmt.Errorf("failed to send AUTH TLS: %w", err)
	}
	
	// Read AUTH TLS response
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read AUTH TLS response: %w", err)
	}
	
	// Check for success (234 response code)
	if !strings.HasPrefix(response, "234") {
		// Some servers might use different codes or AUTH SSL
		if strings.Contains(response, "502") || strings.Contains(response, "500") {
			// Try AUTH SSL as fallback
			_, err = conn.Write([]byte("AUTH SSL\r\n"))
			if err != nil {
				return fmt.Errorf("failed to send AUTH SSL: %w", err)
			}
			
			response, err = reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read AUTH SSL response: %w", err)
			}
			
			if !strings.HasPrefix(response, "234") {
				return fmt.Errorf("server does not support AUTH TLS/SSL: %s", response)
			}
		} else {
			return fmt.Errorf("AUTH TLS failed: %s", response)
		}
	}
	
	return nil
}

// GetStartTLSNegotiator returns the appropriate negotiator for a protocol
func GetStartTLSNegotiator(protocol string) (StartTLSNegotiator, error) {
	switch strings.ToLower(protocol) {
	case "smtp":
		return &SMTPStartTLS{}, nil
	case "imap":
		return &IMAPStartTLS{}, nil
	case "pop3":
		return &POP3StartTLS{}, nil
	case "ftp":
		return &FTPStartTLS{}, nil
	default:
		return nil, fmt.Errorf("unsupported STARTTLS protocol: %s", protocol)
	}
}

// DialWithStartTLS establishes a TLS connection using STARTTLS
func DialWithStartTLS(host, port, protocol string, config *ztls.Config, timeout time.Duration) (*ztls.Conn, error) {
	// First establish plain TCP connection
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	
	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("failed to establish TCP connection: %w", err)
	}
	
	// Get the appropriate negotiator
	negotiator, err := GetStartTLSNegotiator(protocol)
	if err != nil {
		_ = conn.Close() // Best effort cleanup on error
		return nil, err
	}
	
	// Perform STARTTLS negotiation
	if err := negotiator.Negotiate(conn); err != nil {
		_ = conn.Close() // Best effort cleanup on error
		return nil, fmt.Errorf("STARTTLS negotiation failed: %w", err)
	}
	
	// Upgrade to TLS
	tlsConn := ztls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close() // Best effort cleanup on error
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	
	return tlsConn, nil
}