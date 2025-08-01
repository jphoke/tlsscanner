package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

const (
	sslv3Version         = 0x0300
	recordTypeHandshake  = 0x16
	handshakeTypeClientHello = 0x01
	handshakeTypeServerHello = 0x02
)

func main() {
	port := "8443"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = listener.Close() // Clean up test server
	}()

	fmt.Printf("Mock SSL v3 server listening on port %s...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close() // Clean up test connection
	}()
	fmt.Printf("New connection from %s\n", conn.RemoteAddr())

	// Read ClientHello
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}

	// Verify it's a ClientHello
	if n < 5 || buf[0] != recordTypeHandshake {
		fmt.Printf("Not a handshake record\n")
		return
	}

	// Check if it's SSL v3
	recordVersion := binary.BigEndian.Uint16(buf[1:3])
	fmt.Printf("Client record version: 0x%04x\n", recordVersion)

	// Send back a mock ServerHello with SSL v3
	serverHello := buildServerHello()
	_, err = conn.Write(serverHello)
	if err != nil {
		fmt.Printf("Write error: %v\n", err)
		return
	}

	fmt.Printf("Sent SSL v3 ServerHello\n")
}

func buildServerHello() []byte {
	var buf bytes.Buffer

	// Build ServerHello body
	var hello bytes.Buffer
	_ = binary.Write(&hello, binary.BigEndian, uint16(sslv3Version)) // Protocol version
	hello.Write(make([]byte, 32))                                 // Random
	hello.WriteByte(0)                                            // Session ID length
	_ = binary.Write(&hello, binary.BigEndian, uint16(0x0035)) // Cipher suite
	hello.WriteByte(0)                                            // Compression method

	// Build handshake message
	var handshake bytes.Buffer
	handshake.WriteByte(handshakeTypeServerHello)
	length := hello.Len()
	handshake.WriteByte(byte(length >> 16))
	handshake.WriteByte(byte(length >> 8))
	handshake.WriteByte(byte(length))
	handshake.Write(hello.Bytes())

	// Build SSL record
	buf.WriteByte(recordTypeHandshake)
	_ = binary.Write(&buf, binary.BigEndian, uint16(sslv3Version))
	_ = binary.Write(&buf, binary.BigEndian, uint16(handshake.Len()))
	buf.Write(handshake.Bytes())

	return buf.Bytes()
}