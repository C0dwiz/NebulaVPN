package config

import (
	"fmt"
	"os"

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
	} `yaml:"server"`

	Client struct {
		ServerAddress string `yaml:"server_address"`
		LocalPort     int    `yaml:"local_port"`
		TLSSkipVerify bool   `yaml:"tls_skip_verify"`
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
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c.Crypto.Password == "" {
		return fmt.Errorf("crypto password is required")
	}
	return nil
}
