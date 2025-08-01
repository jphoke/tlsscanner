package scanner

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildSSLv3ClientHello(t *testing.T) {
	clientHello := buildSSLv3ClientHello()
	
	// Verify minimum length (5 byte record header + handshake message)
	if len(clientHello) < 5 {
		t.Fatalf("ClientHello too short: %d bytes", len(clientHello))
	}
	
	// Verify record type is handshake (0x16)
	if clientHello[0] != recordTypeHandshake {
		t.Errorf("Expected record type 0x16, got 0x%02x", clientHello[0])
	}
	
	// Verify SSL version in record header
	recordVersion := binary.BigEndian.Uint16(clientHello[1:3])
	if recordVersion != sslv3Version {
		t.Errorf("Expected SSL v3 version (0x0300), got 0x%04x", recordVersion)
	}
	
	// Verify record length matches actual payload
	recordLength := binary.BigEndian.Uint16(clientHello[3:5])
	if int(recordLength) != len(clientHello)-5 {
		t.Errorf("Record length mismatch: header says %d, actual payload is %d", 
			recordLength, len(clientHello)-5)
	}
	
	// Verify handshake type is ClientHello (0x01)
	if len(clientHello) > 5 && clientHello[5] != handshakeTypeClientHello {
		t.Errorf("Expected handshake type 0x01, got 0x%02x", clientHello[5])
	}
}

func TestParseSSLv3Response(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     bool
		wantErr  bool
	}{
		{
			name:     "empty response",
			response: []byte{},
			want:     false,
			wantErr:  true,
		},
		{
			name:     "short response",
			response: []byte{0x16, 0x03, 0x00},
			want:     false,
			wantErr:  true,
		},
		{
			name: "alert response",
			response: []byte{
				0x15,       // Alert record
				0x03, 0x00, // SSL v3
				0x00, 0x02, // Length
				0x02, 0x46, // Fatal, protocol version alert
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "valid ServerHello with SSL v3",
			response: buildMockServerHello(sslv3Version),
			want:     true,
			wantErr:  false,
		},
		{
			name: "ServerHello with TLS 1.0",
			response: buildMockServerHello(0x0301),
			want:     false,
			wantErr:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSSLv3Response(tt.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSSLv3Response() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseSSLv3Response() = %v, want %v", got, tt.want)
			}
		})
	}
}

// buildMockServerHello creates a minimal ServerHello response for testing
func buildMockServerHello(version uint16) []byte {
	var buf bytes.Buffer
	
	// Record header
	buf.WriteByte(recordTypeHandshake)
	binary.Write(&buf, binary.BigEndian, uint16(sslv3Version)) // Record version
	binary.Write(&buf, binary.BigEndian, uint16(42))           // Record length (placeholder)
	
	// Handshake header
	buf.WriteByte(handshakeTypeServerHello)
	buf.Write([]byte{0x00, 0x00, 0x26}) // Handshake length (38 bytes)
	
	// ServerHello body
	binary.Write(&buf, binary.BigEndian, version) // Protocol version
	buf.Write(make([]byte, 32))                   // Random (32 bytes)
	buf.WriteByte(0)                              // Session ID length
	binary.Write(&buf, binary.BigEndian, uint16(0x0035)) // Cipher suite
	buf.WriteByte(0)                              // Compression method
	
	// Fix record length
	response := buf.Bytes()
	binary.BigEndian.PutUint16(response[3:5], uint16(len(response)-5))
	
	return response
}