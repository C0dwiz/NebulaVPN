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

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAndValidate(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	content := `
server:
  host: "127.0.0.1"
  port: 443
  max_connections: 100
  timeout_seconds: 30
  allowed_ips:
    - "192.168.1.100"
  tls:
    cert_path: ""
    key_path: ""
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
  tls_skip_verify: true
  timeout_seconds: 10
  retry_attempts: 3
crypto:
  method: "aes-256-gcm"
  password: "secret123456"
http_mask:
  enabled: true
  domain: "example.com"
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
logging:
  level: "info"
  format: "json"
  file: ""
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate error: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" || cfg.Client.LocalPort != 1080 {
		t.Fatalf("parsed values mismatch: %#v", cfg)
	}

	// Test default values
	if cfg.Server.MaxConnections != 100 {
		t.Fatalf("expected max_connections 100, got %d", cfg.Server.MaxConnections)
	}
	if cfg.Server.Timeout != 30 {
		t.Fatalf("expected timeout 30, got %d", cfg.Server.Timeout)
	}
	if cfg.Client.Timeout != 10 {
		t.Fatalf("expected client timeout 10, got %d", cfg.Client.Timeout)
	}
	if cfg.Logging.Level != "info" {
		t.Fatalf("expected log level info, got %s", cfg.Logging.Level)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "valid config",
			config: `
server:
  host: "127.0.0.1"
  port: 443
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
crypto:
  method: "aes-256-gcm"
  password: "validpassword123"
`,
			wantErr: false,
		},
		{
			name: "missing password",
			config: `
server:
  host: "127.0.0.1"
  port: 443
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
crypto:
  method: "aes-256-gcm"
  password: ""
`,
			wantErr: true,
		},
		{
			name: "short password",
			config: `
server:
  host: "127.0.0.1"
  port: 443
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
crypto:
  method: "aes-256-gcm"
  password: "short"
`,
			wantErr: true,
		},
		{
			name: "invalid port",
			config: `
server:
  host: "127.0.0.1"
  port: 70000
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
crypto:
  method: "aes-256-gcm"
  password: "validpassword123"
`,
			wantErr: true,
		},
		{
			name: "invalid encryption method",
			config: `
server:
  host: "127.0.0.1"
  port: 443
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
crypto:
  method: "invalid-method"
  password: "validpassword123"
`,
			wantErr: true,
		},
		{
			name: "invalid log level",
			config: `
server:
  host: "127.0.0.1"
  port: 443
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
crypto:
  method: "aes-256-gcm"
  password: "validpassword123"
logging:
  level: "invalid"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgPath := filepath.Join(tmpDir, "config.yaml")

			if err := os.WriteFile(cfgPath, []byte(tt.config), 0o600); err != nil {
				t.Fatalf("write temp config: %v", err)
			}

			cfg, err := LoadConfig(cfgPath)
			if err != nil {
				t.Fatalf("LoadConfig error: %v", err)
			}

			err = cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// Minimal config
	content := `
server:
  host: "127.0.0.1"
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

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	// Test default values are set
	if cfg.Server.MaxConnections != 1000 {
		t.Fatalf("expected default max_connections 1000, got %d", cfg.Server.MaxConnections)
	}
	if cfg.Server.Timeout != 30 {
		t.Fatalf("expected default timeout 30, got %d", cfg.Server.Timeout)
	}
	if cfg.Client.Timeout != 10 {
		t.Fatalf("expected default client timeout 10, got %d", cfg.Client.Timeout)
	}
	if cfg.Client.RetryAttempts != 3 {
		t.Fatalf("expected default retry attempts 3, got %d", cfg.Client.RetryAttempts)
	}
	if cfg.Logging.Level != "info" {
		t.Fatalf("expected default log level info, got %s", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Fatalf("expected default log format json, got %s", cfg.Logging.Format)
	}
}
