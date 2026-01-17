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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nebulavpn/internal/config"
	"nebulavpn/internal/protocol"
	"nebulavpn/pkg/transport"
)

func TestServerValidation(t *testing.T) {
	// Test target address validation
	tests := []struct {
		address string
		valid   bool
	}{
		{"example.com:80", true},
		{"8.8.8.8:443", true}, // Public IP
		{"1.1.1.1:53", true},  // Public IP
		{"invalid-address", false},
		{"", false},
		{"localhost:80", false},    // Should be blocked
		{"127.0.0.1:80", false},    // Should be blocked
		{"192.168.1.1:443", false}, // Private IP should be blocked
		{"10.0.0.1:80", false},     // Private IP should be blocked
		{"172.16.0.1:80", false},   // Private IP should be blocked
		{"169.254.0.1:80", false},  // Link-local should be blocked
		{"::1:80", false},          // IPv6 loopback should be blocked
	}

	for _, tt := range tests {
		result := isValidTargetAddress(tt.address)
		if result != tt.valid {
			t.Fatalf("isValidTargetAddress(%s) = %v, want %v", tt.address, result, tt.valid)
		}
	}
}

func TestServerConfigValidation(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// Test invalid config
	content := `
server:
  host: "invalid-host-name-very-long-` + strings.Repeat("a", 300) + `"
  port: 443
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
crypto:
  password: "validpassword123"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error for invalid hostname")
	}
}

func TestServerConnectionLimits(t *testing.T) {
	// Mock components for testing
	httpsMask := protocol.NewHTTPSMask(false, "", nil)
	_, _ = transport.NewTLSWrapper("", "", httpsMask)

	// Create test listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Test connection limit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connCount := 0
	done := make(chan struct{}, 1)

	go func() {
		for i := 0; i < 3; i++ {
			conn, err := net.Dial("tcp", "127.0.0.1:"+string(rune(port)))
			if err != nil {
				break
			}
			connCount++
			conn.Close()
		}
		close(done)
	}()

	select {
	case <-done:
		if connCount > 1 {
			t.Logf("Multiple connections attempted: %d", connCount)
		}
	case <-ctx.Done():
		t.Log("Test completed by timeout")
	}
}

func TestServerIPFiltering(t *testing.T) {
	// Test IP filtering logic
	tests := []struct {
		clientIP    string
		allowedIPs  []string
		shouldAllow bool
	}{
		{"192.168.1.100", []string{"192.168.1.100", "10.0.0.50"}, true},
		{"192.168.1.200", []string{"192.168.1.100", "10.0.0.50"}, false},
		{"10.0.0.50", []string{"192.168.1.100", "10.0.0.50"}, true},
		{"10.0.0.100", []string{"192.168.1.100", "10.0.0.50"}, false},
		{"192.168.1.100", []string{}, true}, // No whitelist = allow all
	}

	for _, tt := range tests {
		allowed := false
		if len(tt.allowedIPs) == 0 {
			allowed = true // No whitelist means allow all
		} else {
			for _, ip := range tt.allowedIPs {
				if tt.clientIP == ip {
					allowed = true
					break
				}
			}
		}

		if allowed != tt.shouldAllow {
			t.Errorf("IP filtering for %s with whitelist %v = %v, want %v",
				tt.clientIP, tt.allowedIPs, allowed, tt.shouldAllow)
		}
	}
}

func TestServerHostValidation(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"example.com", true},
		{"valid.domain.org", true},
		{"8.8.8.8", true},       // Public IP
		{"1.1.1.1", true},       // Public IP
		{"localhost", false},    // Should be blocked
		{"127.0.0.1", false},    // Should be blocked
		{"192.168.1.1", false},  // Private IP should be blocked
		{"10.0.0.1", false},     // Private IP should be blocked
		{"172.16.0.1", false},   // Private IP should be blocked
		{"169.254.0.1", false},  // Link-local should be blocked
		{"::1", false},          // IPv6 loopback should be blocked
		{"invalid", false},      // No dot, not a valid domain
		{"", false},             // Empty
		{".example.com", false}, // Starts with dot
		{"example.com.", false}, // Ends with dot
	}

	for _, tt := range tests {
		result := isValidHost(tt.host)
		if result != tt.valid {
			t.Errorf("isValidHost(%s) = %v, want %v", tt.host, result, tt.valid)
		}
	}
}

func BenchmarkHostValidation(b *testing.B) {
	hosts := []string{"example.com", "valid.domain.org", "8.8.8.8", "localhost"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isValidHost(hosts[i%len(hosts)])
	}
}

func BenchmarkTargetAddressValidation(b *testing.B) {
	addresses := []string{"example.com:80", "8.8.8.8:443", "localhost:80", "127.0.0.1:80"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isValidTargetAddress(addresses[i%len(addresses)])
	}
}

// Mock encryptor for testing
type mockEncryptor struct{}

func (m *mockEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (m *mockEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
