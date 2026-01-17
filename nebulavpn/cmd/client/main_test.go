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
	"testing"
	"time"

	"nebulavpn/internal/config"
	"nebulavpn/internal/protocol"
	"nebulavpn/pkg/transport"
)

func TestClientValidation(t *testing.T) {
	// Test domain validation
	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"test-domain.org", true},
		{"valid.domain.co.uk", true},
		{"invalid", false},                 // No dot, not a valid domain
		{"", false},                        // Empty
		{".example.com", false},            // Starts with dot
		{"example.com.", false},            // Ends with dot
		{"example..com", false},            // Double dot
		{"-example.com", false},            // Starts with hyphen
		{"example-.com", false},            // Ends with hyphen
		{"exa$mple.com", false},            // Invalid character
		{string(make([]byte, 254)), false}, // Too long
		{"localhost", false},               // Should be blocked
		{"127.0.0.1", false},               // Should be blocked
		{"192.168.1.1", false},             // Private IP should be blocked
		{"10.0.0.1", false},                // Private IP should be blocked
	}

	for _, tt := range tests {
		result := isValidDomain(tt.domain)
		if result != tt.valid {
			t.Errorf("isValidDomain(%s) = %v, want %v", tt.domain, result, tt.valid)
		}
	}
}

func TestClientConfigValidation(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// Test invalid config
	content := `
client:
  server_address: "invalid-address"
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
		t.Fatalf("expected validation error for invalid server address")
	}
}

func TestClientConnectionHandling(t *testing.T) {
	// Mock components for testing
	encryptor := &mockEncryptor{}
	httpsMask := protocol.NewHTTPSMask(false, "", nil)
	tlsWrapper, _ := transport.NewTLSWrapper("", "", httpsMask)

	// Create test listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	cfg := &config.Config{
		Client: struct {
			ServerAddress string `yaml:"server_address"`
			LocalPort     int    `yaml:"local_port"`
			TLSSkipVerify bool   `yaml:"tls_skip_verify"`
			Timeout       int    `yaml:"timeout_seconds"`
			RetryAttempts int    `yaml:"retry_attempts"`
		}{
			ServerAddress: "127.0.0.1:" + string(rune(port)),
			LocalPort:     1080,
			Timeout:       10,
		},
	}

	// Test connection handling with context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		clientConn, err := net.Dial("tcp", "127.0.0.1:"+string(rune(port)))
		if err != nil {
			done <- err
			return
		}
		defer clientConn.Close()

		handleClientConnection(ctx, clientConn, cfg, encryptor, tlsWrapper)
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("Connection error (expected in test): %v", err)
		}
	case <-ctx.Done():
		t.Log("Test completed by timeout")
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

func BenchmarkDomainValidation(b *testing.B) {
	domains := []string{"example.com", "sub.example.com", "test-domain.org", "invalid-domain"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isValidDomain(domains[i%len(domains)])
	}
}
