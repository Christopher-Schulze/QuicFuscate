package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"time"
)

// LoadClientConfig lädt die Client-Konfiguration aus einer YAML-Datei
func LoadClientConfig(path string) (*ClientConfig, error) {
	// Überprüfen, ob die Datei existiert
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file %s does not exist", path)
	}

	// YAML-Datei einlesen
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Konfiguration parsen
	config := &ClientConfig{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Basis-Validierung
	if config.ServerAddr == "" {
		return nil, fmt.Errorf("server_addr is required in config")
	}
	if config.MTU <= 0 {
		config.MTU = 1500 // Standard-MTU
	}

	// Standardwerte für FEC, falls nicht gesetzt
	if config.FEC.Codec == "" {
		config.FEC.Codec = "tetrys"
	}
	if config.FEC.MaxRedundancy <= 0 {
		config.FEC.MaxRedundancy = 0.2 // 20% Redundanz
	}

	// Standardwerte für Keepalive, falls nicht gesetzt
	if config.Keepalive.Interval <= 0 {
		config.Keepalive.Interval = 30 * time.Second
	}
	if config.Keepalive.Timeout <= 0 {
		config.Keepalive.Timeout = 10 * time.Second
	}

	return config, nil
}
