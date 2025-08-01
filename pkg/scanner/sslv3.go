// Package scanner implements SSL/TLS scanning functionality.
//
//nolint:err113 // This file uses dynamic errors to provide detailed protocol-specific feedback
package scanner

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	sslv3Version       = 0x0300
	recordTypeHandshake = 0x16
	recordTypeAlert     = 0x15
	handshakeTypeClientHello = 0x01
	handshakeTypeServerHello = 0x02
)

// Common SSL v3 cipher suites
var sslv3CipherSuites = []uint16{
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0005, // TLS_RSA_WITH_RC4_128_SHA
	0x0004, // TLS_RSA_WITH_RC4_128_MD5
	0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x0009, // TLS_RSA_WITH_DES_CBC_SHA
	0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
	0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
}

// TestSSLv3 attempts to detect SSL v3 support using raw sockets
func TestSSLv3(host string, port string) (bool, error) {
	// Establish TCP connection with timeout
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return false, fmt.Errorf("connection failed: %w", err)
	}
	defer func() {
		_ = conn.Close() // Clean up SSL v3 test connection
	}()

	// Set read timeout
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Best effort timeout

	// Build and send SSL v3 ClientHello
	clientHello, err := buildSSLv3ClientHello()
	if err != nil {
		return false, fmt.Errorf("failed to build ClientHello: %w", err)
	}
	if _, err := conn.Write(clientHello); err != nil {
		return false, fmt.Errorf("failed to send ClientHello: %w", err)
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response to determine if SSL v3 is supported
	supported, err := parseSSLv3Response(response[:n])
	if err != nil {
		// Log the first few bytes of the response for debugging
		if n >= 5 {
			fmt.Printf("DEBUG: SSL v3 response first 5 bytes: %02x %02x %02x %02x %02x\n", 
				response[0], response[1], response[2], response[3], response[4])
		}
	}
	return supported, err
}

// buildSSLv3ClientHello constructs an SSL v3 ClientHello message
func buildSSLv3ClientHello() ([]byte, error) {
	var buf bytes.Buffer

	// Generate 32 random bytes (4 bytes timestamp + 28 random)
	randomBytes := make([]byte, 32)
	binary.BigEndian.PutUint32(randomBytes[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(randomBytes[4:]); err != nil {
		// This should never fail with crypto/rand
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Build ClientHello body
	var clientHello bytes.Buffer
	
	// Protocol version (SSL 3.0)
	_ = binary.Write(&clientHello, binary.BigEndian, uint16(sslv3Version)) // Writing to buffer cannot fail
	
	// Random
	clientHello.Write(randomBytes)
	
	// Session ID length (0 - no session resumption)
	clientHello.WriteByte(0)
	
	// Cipher suites length
	_ = binary.Write(&clientHello, binary.BigEndian, uint16(len(sslv3CipherSuites)*2)) // Writing to buffer cannot fail
	
	// Cipher suites
	for _, suite := range sslv3CipherSuites {
		_ = binary.Write(&clientHello, binary.BigEndian, suite) // Writing to buffer cannot fail
	}
	
	// Compression methods length
	clientHello.WriteByte(1)
	
	// Compression method (NULL)
	clientHello.WriteByte(0)

	// Build handshake message
	var handshake bytes.Buffer
	
	// Handshake type (ClientHello)
	handshake.WriteByte(handshakeTypeClientHello)
	
	// Handshake length (3 bytes)
	length := clientHello.Len()
	handshake.WriteByte(byte(length >> 16))
	handshake.WriteByte(byte(length >> 8))
	handshake.WriteByte(byte(length))
	
	// Handshake body
	handshake.Write(clientHello.Bytes())

	// Build SSL record
	// Record type (Handshake)
	buf.WriteByte(recordTypeHandshake)
	
	// SSL version
	_ = binary.Write(&buf, binary.BigEndian, uint16(sslv3Version)) // Writing to buffer cannot fail
	
	// Record length
	_ = binary.Write(&buf, binary.BigEndian, uint16(handshake.Len())) // Writing to buffer cannot fail
	
	// Record payload
	buf.Write(handshake.Bytes())

	return buf.Bytes(), nil
}

// parseSSLv3Response analyzes the server response to determine SSL v3 support
func parseSSLv3Response(data []byte) (bool, error) {
	if len(data) < 5 {
		return false, errors.New("response too short")
	}

	// Check record type
	recordType := data[0]
	
	// Check SSL version in record header
	recordVersion := binary.BigEndian.Uint16(data[1:3])
	
	// Get record length
	recordLength := binary.BigEndian.Uint16(data[3:5])
	
	// Validate record version is SSL v3
	if recordVersion != sslv3Version {
		return false, fmt.Errorf("unexpected record version: 0x%04x", recordVersion)
	}
	
	if len(data) < int(5+recordLength) {
		return false, errors.New("incomplete record")
	}

	switch recordType {
	case recordTypeHandshake:
		// Parse handshake message
		if len(data) < 9 { // 5 (record) + 4 (handshake header)
			return false, errors.New("handshake message too short")
		}
		
		handshakeType := data[5]
		if handshakeType == handshakeTypeServerHello {
			// Check protocol version in ServerHello (offset 5 + 4 = 9)
			if len(data) >= 11 {
				serverVersion := binary.BigEndian.Uint16(data[9:11])
				// Server accepted SSL v3 if it responds with SSL v3 version
				return serverVersion == sslv3Version, nil
			}
		}
		
	case recordTypeAlert:
		// Server sent an alert - SSL v3 not supported or other error
		// Could parse alert level and description for more details
		return false, nil
	}

	// Unknown or unexpected response
	return false, fmt.Errorf("unexpected record type: %d", recordType)
}