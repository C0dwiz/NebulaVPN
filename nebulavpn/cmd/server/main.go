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
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
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

	tlsWrapper, err := transport.NewTLSWrapper(
		cfg.Server.TLS.CertPath,
		cfg.Server.TLS.KeyPath,
		httpsMask,
	)
	if err != nil {
		log.Fatalf("Failed to create TLS wrapper: %v", err)
	}

	listener, err := tlsWrapper.Listen("tcp",
		fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port))
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	log.Printf("Server started on %s:%d", cfg.Server.Host, cfg.Server.Port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	var connectionCount int64

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
		listener.Close()
		wg.Wait()
		log.Printf("Server shutdown complete. Handled %d connections", atomic.LoadInt64(&connectionCount))
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

		// Check connection limit
		currentConnections := atomic.LoadInt64(&connectionCount)
		if currentConnections >= int64(cfg.Server.MaxConnections) {
			log.Printf("Connection limit reached (%d), rejecting new connection", cfg.Server.MaxConnections)
			clientConn.Close()
			continue
		}

		// Validate client IP if allowed IPs are configured
		if len(cfg.Server.AllowedIPs) > 0 {
			clientAddr := clientConn.RemoteAddr().String()
			host, _, err := net.SplitHostPort(clientAddr)
			if err != nil {
				log.Printf("Failed to parse client address: %v", err)
				clientConn.Close()
				continue
			}

			allowed := false
			for _, allowedIP := range cfg.Server.AllowedIPs {
				if host == allowedIP {
					allowed = true
					break
				}
			}
			if !allowed {
				log.Printf("Connection from unauthorized IP: %s", host)
				clientConn.Close()
				continue
			}
		}

		atomic.AddInt64(&connectionCount, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer atomic.AddInt64(&connectionCount, -1)
			handleServerConnection(ctx, clientConn, encryptor, cfg)
		}()
	}
}

func handleServerConnection(ctx context.Context, clientConn net.Conn, encryptor crypto.Encryptor, cfg *config.Config) {
	defer clientConn.Close()

	// Set connection timeout
	timeout := time.Duration(cfg.Server.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	clientConn.SetDeadline(time.Now().Add(timeout))

	tun := tunnel.NewTunnel(encryptor)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, targetAddr, err := tun.ReadPacket(clientConn)
		if err != nil {
			log.Printf("Failed to read packet: %v", err)
			return
		}

		// Validate target address
		if !isValidTargetAddress(targetAddr) {
			log.Printf("Invalid target address: %s", targetAddr)
			return
		}

		// Reset deadline for each packet
		clientConn.SetDeadline(time.Now().Add(timeout))

		go forwardToTarget(ctx, data, targetAddr, clientConn, tun, timeout)
	}
}

func forwardToTarget(ctx context.Context, data []byte, targetAddr string,
	clientConn net.Conn, tun *tunnel.Tunnel, timeout time.Duration) {

	// Validate target address format
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		log.Printf("Invalid target address format %s: %v", targetAddr, err)
		return
	}

	// Additional validation
	if !isValidHost(host) {
		log.Printf("Invalid host in target address: %s", host)
		return
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Set timeout for target connection
	targetConn.SetDeadline(time.Now().Add(timeout))

	if _, err := targetConn.Write(data); err != nil {
		log.Printf("Failed to write to %s: %v", targetAddr, err)
		return
	}

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Reset deadline for each read
		targetConn.SetReadDeadline(time.Now().Add(timeout))
		n, err := targetConn.Read(buf)
		if err != nil {
			break
		}

		if err := tun.WritePacket(clientConn, buf[:n], targetAddr); err != nil {
			log.Printf("Failed to send packet to client: %v", err)
			break
		}
	}
}

// isValidTargetAddress performs basic validation of target addresses
func isValidTargetAddress(addr string) bool {
	if addr == "" {
		return false
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	return isValidHost(host) && isValidPort(port)
}

// isValidHost validates hostnames and IP addresses
func isValidHost(host string) bool {
	if host == "" {
		return false
	}

	// Block localhost and loopback addresses first
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}

	// Check if it's an IP address
	ip := net.ParseIP(host)
	if ip != nil {
		// Block private IP ranges, loopback, and link-local for security
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return false
		}
		return true
	}

	// Basic hostname validation
	if len(host) > 253 {
		return false
	}

	// Enhanced validation for domain names
	for _, ch := range host {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
			return false
		}
	}

	// Check for valid domain structure (dots and labels)
	if host[0] == '.' || host[len(host)-1] == '.' {
		return false
	}

	// Split by dots and validate each label
	labels := strings.Split(host, ".")
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

// isValidPort validates port numbers
func isValidPort(port string) bool {
	portNum, err := net.LookupPort("tcp", port)
	return err == nil && portNum > 0 && portNum <= 65535
}
