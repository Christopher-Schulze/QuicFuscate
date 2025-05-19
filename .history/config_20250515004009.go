package main

import (
	"gopkg.in/yaml.v3"
	"os"
)

// Config represents the configuration for StealthQUIC-VPN
type Config struct {
	Server struct {
		Address       string `yaml:"address"`
		CACert        string `yaml:"ca_cert"`
		MetricsAddress string `yaml:"metrics_address"`
	} `yaml:"server"`

	FEC struct {
		RaptorQ struct {
			Enabled    bool    `yaml:"enabled"`
			Redundancy float64 `yaml:"redundancy"`
		} `yaml:"raptorq"`
		Tetrys struct {
			Enabled    bool    `yaml:"enabled"`
			Redundancy float64 `yaml:"redundancy"`
		} `yaml:"tetrys"`
	} `yaml:"fec"`

	TLS struct {
		SNI         []string `yaml:"sni"`
		CipherSuites []string `yaml:"cipher_suites"`
	} `yaml:"tls"`

	Keepalive struct {
		Interval int `yaml:"interval"`
	} `yaml:"keepalive"`

	Logging struct {
		Level   string `yaml:"level"`
		Verbose bool   `yaml:"verbose"`
	} `yaml:"logging"`
}

// loadConfig loads configuration from a YAML file
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
