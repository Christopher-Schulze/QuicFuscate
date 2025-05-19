package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"github.com/lajosbencz/gos"
	"github.com/xtaci/tetrys"
)

// Client-Konfiguration aus config.yaml
type ClientConfig struct {
	ServerAddr string `yaml:"server_addr"`
	MTU        int    `yaml:"mtu"`
	// Encryption-Konfiguration
	Encryption struct {
		Enabled   bool   `yaml:"enabled"`
		Algorithm string `yaml:"algorithm"` // "aes-256-gcm" oder "chacha20-poly1305"
		Key       string `yaml:"key"`       // Base64-kodierter Schlüssel
	} `yaml:"encryption"`
	// FEC-Konfiguration
	FEC struct {
		Enabled   bool   `yaml:"enabled"`
		Codec     string `yaml:"codec"` // "raptorq" oder "tetrys"
		MaxRedundancy float32 `yaml:"max_redundancy"`
	} `yaml:"fec"`
	// Keepalive-Konfiguration
	Keepalive struct {
		Interval time.Duration `yaml:"interval"`
		Timeout  time.Duration `yaml:"timeout"`
	} `yaml:"keepalive"`
}

func main() {
	configPath := flag.String("config", "client/config.yaml", "Path to client configuration file")
	flag.Parse()

	// Konfigurationsdatei laden
	config, err := LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load client config: %v", err)
	}

	// QUIC-Verbindung mit Fake TLS herstellen
	session, err := DialWithFakeTLS(config.ServerAddr)
	if err != nil {
		log.Fatalf("QUIC connection failed: %v", err)
	}
	defer session.CloseWithError(0, "client shutdown")

	// TUN-Schnittstelle erstellen
	ifce, err := water.NewTUN("quicsand0", config.MTU)
	if err != nil {
		log.Fatalf("TUN creation failed: %v", err)
	}
	defer ifce.Close()

	// FEC-Encoder initialisieren
	var encoder FEC
	switch config.FEC.Codec {
	case "raptorq":
		encoder = gos.NewRaptorQEncoder(config.FEC.MaxRedundancy)
	case "tetrys":
		encoder = tetrys.NewTetrysEncoder(config.FEC.MaxRedundancy)
	default:
		encoder = &NoFEC{}
	}

	// Keepalive-Loop starten
	go func() {
		ticker := time.NewTicker(config.Keepalive.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err := SendKeepalive(session, config)
				if err != nil {
					log.Printf("Keepalive failed: %v", err)
				}
			}
		}
	}()

	// Haupt-VPN-Logik
	go func() {
		stream, err := session.OpenStream()
		if err != nil {
			log.Fatalf("Stream creation failed: %v", err)
		}
		defer stream.Close()

		// Paket-Forwarding zwischen TUN und QUIC-Stream
		for {
			buf := make([]byte, config.MTU)
			n, err := ifce.Read(buf)
			if err != nil {
				log.Printf("TUN read failed: %v", err)
				continue
			}

			// FEC-Codierung anwenden
			var encodedData []byte
			if config.FEC.Enabled {
				encodedData = encoder.Encode(buf[:n])
			} else {
				encodedData = buf[:n]
			}
			
			// Verschlüsselung und Fake TLS (wird später implementiert)
			encrypted := ApplyEncryption(encodedData, config.Encryption)
			_, err = stream.Write(encrypted)
			if err != nil {
				log.Printf("Stream write failed: %v", err)
			}
		}
	}()

	// Blockierender Aufruf zum Aufrechterhalten des Clients
	select {}
}

// Dummy-FEC-Implementierung
type NoFEC struct{}

func (n *NoFEC) Encode(data []byte) []byte { return data }
func (n *NoFEC) Decode(data []byte) []byte { return data }

// Client-Konfigurationslader (wird später vervollständigt)
func LoadClientConfig(path string) (*ClientConfig, error) {
	// Implementierung aus config.go wiederverwenden
	encryptionConfig := &EncryptionConfig{
		Enabled:   config.Encryption.Enabled,
		Algorithm: config.Encryption.Algorithm,
		Key:       config.Encryption.Key,
	}
	return &ClientConfig{
		ServerAddr: config.ServerAddr,
		MTU:        config.MTU,
		Encryption: encryptionConfig,
		FEC:        config.FEC,
		Keepalive:  config.Keepalive,
	}, nil
}

// Keepalive-Implementierung (wird später vervollständigt)
func SendKeepalive(session quic.Session, config *ClientConfig) error {
	stream, err := session.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()
	_, err = stream.Write([]byte("keepalive"))
	return err
}
