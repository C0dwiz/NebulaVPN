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
  tls:
    cert_path: ""
    key_path: ""
client:
  server_address: "127.0.0.1:443"
  local_port: 1080
  tls_skip_verify: true
crypto:
  method: "aes-256-gcm"
  password: "secret"
http_mask:
  enabled: true
  domain: "example.com"
  user_agents:
    - "UA"
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
}
