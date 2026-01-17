// MIT License
//
// Copyright (c) 2026 CodWiz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"nebulavpn/internal/config"
	"nebulavpn/internal/crypto"
	"nebulavpn/internal/protocol"
	"nebulavpn/pkg/transport"
	"nebulavpn/pkg/tunnel"
)

func main() {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Config validation failed: %v", err)
	}

	encryptor, err := crypto.NewEncryptor(cfg.Crypto.Method, cfg.Crypto.Password)
	if err != nil {
		log.Fatalf("Failed to create encryptor: %v", err)
	}

	httpsMask := protocol.NewHTTPSMask(
		cfg.HTTPMask.Enabled,
		cfg.HTTPMask.Domain,
		cfg.HTTPMask.UserAgents,
	)

	tlsWrapper, err := transport.NewTLSWrapper("", "", httpsMask)
	if err != nil {
		log.Fatalf("Failed to create TLS wrapper: %v", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Client.LocalPort))
	if err != nil {
		log.Fatalf("Failed to start local proxy: %v", err)
	}
	defer listener.Close()

	log.Printf("Client started on port %d", cfg.Client.LocalPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
		listener.Close()
		wg.Wait()
		os.Exit(0)
	}()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleClientConnection(ctx, clientConn, cfg, encryptor, tlsWrapper)
		}()
	}
}

func handleClientConnection(ctx context.Context, clientConn net.Conn, cfg *config.Config,
	encryptor crypto.Encryptor, tlsWrapper *transport.TLSWrapper) {
	defer clientConn.Close()

	// Set connection timeout
	timeout := time.Duration(cfg.Client.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	serverConn, err := tlsWrapper.DialWithTimeout("tcp", cfg.Client.ServerAddress, timeout)
	if err != nil {
		log.Printf("Failed to connect to server: %v", err)
		return
	}
	defer serverConn.Close()

	log.Printf("Connected to server %s", cfg.Client.ServerAddress)

	tun := tunnel.NewTunnel(encryptor)

	// Set read timeout for SOCKS5 handshake
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 256)
	if _, err := clientConn.Read(buf); err != nil {
		log.Printf("Failed to read SOCKS5 request: %v", err)
		return
	}

	// Validate SOCKS5 version
	if buf[0] != 0x05 {
		log.Printf("Invalid SOCKS version: %d", buf[0])
		return
	}

	clientConn.Write([]byte{0x05, 0x00})

	n, err := clientConn.Read(buf)
	if err != nil {
		log.Printf("Failed to read connect request: %v", err)
		return
	}

	// Clear deadline after handshake
	clientConn.SetReadDeadline(time.Time{})

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			log.Printf("Invalid IPv4 address length")
			return
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
	case 0x03: // Domain name
		if n < 5 {
			log.Printf("Invalid domain name format")
			return
		}
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			log.Printf("Invalid domain name length")
			return
		}
		host = string(buf[5 : 5+domainLen])
		// Validate domain name
		if !isValidDomain(host) {
			log.Printf("Invalid domain name: %s", host)
			return
		}
	case 0x04: // IPv6
		if n < 22 {
			log.Printf("Invalid IPv6 address length")
			return
		}
		host = net.IP(buf[4:20]).String()
	default:
		log.Printf("Unsupported address type: %d", buf[3])
		return
	}

	port := binary.BigEndian.Uint16(buf[n-2:])
	if port == 0 {
		log.Printf("Invalid port: 0")
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)

	log.Printf("Connecting to %s", targetAddr)

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Start bidirectional forwarding
	go func() {
		if err := tun.Pipe(ctx, clientConn, serverConn, targetAddr); err != nil {
			log.Printf("Client to server error: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, addr, err := tun.ReadPacket(serverConn)
		if err != nil {
			log.Printf("Failed to read packet from server: %v", err)
			break
		}

		if addr != targetAddr {
			log.Printf("Address mismatch: expected %s, got %s", targetAddr, addr)
			continue
		}

		if _, err := clientConn.Write(data); err != nil {
			log.Printf("Failed to write to client: %v", err)
			break
		}
	}
}

// isValidDomain performs enhanced domain name validation
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Block localhost and IP addresses
	if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
		return false
	}

	// Check if it's an IP address and block it
	if net.ParseIP(domain) != nil {
		return false
	}

	// Enhanced validation for domain names
	for _, ch := range domain {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
			return false
		}
	}

	// Check for valid domain structure (dots and labels)
	if domain[0] == '.' || domain[len(domain)-1] == '.' {
		return false
	}

	// Split by dots and validate each label
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false // Must have at least one dot
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// Each label must start and end with alphanumeric, can contain hyphens in middle
		for i, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || (ch == '-' && i > 0 && i < len(label)-1)) {
				return false
			}
		}
	}

	return true
}
