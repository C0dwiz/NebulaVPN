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
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
		TLS  struct {
			CertPath string `yaml:"cert_path"`
			KeyPath  string `yaml:"key_path"`
		} `yaml:"tls"`
		// Security settings
		MaxConnections int      `yaml:"max_connections"`
		Timeout        int      `yaml:"timeout_seconds"`
		AllowedIPs     []string `yaml:"allowed_ips"`
	} `yaml:"server"`

	Client struct {
		ServerAddress string `yaml:"server_address"`
		LocalPort     int    `yaml:"local_port"`
		TLSSkipVerify bool   `yaml:"tls_skip_verify"`
		// Security settings
		Timeout       int `yaml:"timeout_seconds"`
		RetryAttempts int `yaml:"retry_attempts"`
	} `yaml:"client"`

	Crypto struct {
		Method   string `yaml:"method"`
		Password string `yaml:"password"`
	} `yaml:"crypto"`

	HTTPMask struct {
		Enabled    bool     `yaml:"enabled"`
		Domain     string   `yaml:"domain"`
		UserAgents []string `yaml:"user_agents"`
	} `yaml:"http_mask"`

	// Logging configuration
	Logging struct {
		Level  string `yaml:"level"`
		File   string `yaml:"file"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Set default values
	if config.Server.MaxConnections == 0 {
		config.Server.MaxConnections = 1000
	}
	if config.Server.Timeout == 0 {
		config.Server.Timeout = 30
	}
	if config.Client.Timeout == 0 {
		config.Client.Timeout = 10
	}
	if config.Client.RetryAttempts == 0 {
		config.Client.RetryAttempts = 3
	}
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}

	return config, nil
}

func (c *Config) Validate() error {
	// Validate crypto settings
	if c.Crypto.Password == "" {
		return fmt.Errorf("crypto password is required")
	}
	if len(c.Crypto.Password) < 8 {
		return fmt.Errorf("crypto password must be at least 8 characters long")
	}

	// Validate encryption method
	validMethods := []string{"aes-256-gcm", "chacha20-poly1305"}
	if c.Crypto.Method != "" {
		valid := false
		for _, method := range validMethods {
			if c.Crypto.Method == method {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid encryption method: %s", c.Crypto.Method)
		}
	}

	// Validate server settings
	if c.Server.Host != "" {
		if net.ParseIP(c.Server.Host) == nil && !isValidHostname(c.Server.Host) {
			return fmt.Errorf("invalid server host: %s", c.Server.Host)
		}
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535")
	}
	if c.Server.MaxConnections < 1 {
		return fmt.Errorf("max connections must be at least 1")
	}

	// Validate client settings
	if c.Client.ServerAddress != "" {
		host, port, err := net.SplitHostPort(c.Client.ServerAddress)
		if err != nil {
			return fmt.Errorf("invalid server address format: %s", c.Client.ServerAddress)
		}
		if net.ParseIP(host) == nil && !isValidHostname(host) {
			return fmt.Errorf("invalid server address host: %s", host)
		}
		if portNum, err := net.LookupPort("tcp", port); err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid server address port: %s", port)
		}
	}
	if c.Client.LocalPort < 1 || c.Client.LocalPort > 65535 {
		return fmt.Errorf("client local port must be between 1 and 65535")
	}

	// Validate TLS settings
	if c.Server.TLS.CertPath != "" {
		if _, err := os.Stat(c.Server.TLS.CertPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file not found: %s", c.Server.TLS.CertPath)
		}
	}
	if c.Server.TLS.KeyPath != "" {
		if _, err := os.Stat(c.Server.TLS.KeyPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", c.Server.TLS.KeyPath)
		}
	}

	// Validate HTTP mask settings
	if c.HTTPMask.Enabled {
		if c.HTTPMask.Domain == "" {
			return fmt.Errorf("HTTP mask domain is required when HTTP mask is enabled")
		}
		if !isValidHostname(c.HTTPMask.Domain) {
			return fmt.Errorf("invalid HTTP mask domain: %s", c.HTTPMask.Domain)
		}
		if len(c.HTTPMask.UserAgents) == 0 {
			return fmt.Errorf("user agents are required when HTTP mask is enabled")
		}
	}

	// Validate allowed IPs if specified
	if len(c.Server.AllowedIPs) > 0 {
		for _, ip := range c.Server.AllowedIPs {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid allowed IP address: %s", ip)
			}
		}
	}

	// Validate logging settings
	validLogLevels := []string{"debug", "info", "warn", "error"}
	valid := false
	for _, level := range validLogLevels {
		if c.Logging.Level == level {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}

// isValidHostname checks if a string is a valid hostname
func isValidHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}

	// Remove trailing dot if present
	hostname = strings.TrimSuffix(hostname, ".")

	// Regular expression for hostname validation
	re := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return re.MatchString(hostname)
}
