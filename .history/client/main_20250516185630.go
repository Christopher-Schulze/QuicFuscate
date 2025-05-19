package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"github.com/lajosbencz/gos"
	"QuicSand/tetrys"
	"gopkg.in/yaml.v2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"encoding/base64"
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

	// QUIC-Verbindung mit Client Certificate
	session, err := DialWithClientCert(config.ServerAddr, config)
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

// Client-Konfigurationslader
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config ClientConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// QUIC-Verbindung mit Client Certificate
func DialWithClientCert(addr string, config *ClientConfig) (quic.Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	// Load client certificate and private key
	certPEM, err := os.ReadFile(config.ClientCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(config.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read client key: %w", err)
	}

	// Parse certificate and private key
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	// Create TLS config with client certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      config.CA,
		NextProtos:   []string{"quic-echo-example"},
	}

	conn, err := quic.DialAddr(udpAddr.String(), &quic.Config{
		TLSConfig: tlsConfig,
	})
	return conn, err
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

func ApplyEncryption(data []byte, encryption EncryptionConfig) []byte {
	if !encryption.Enabled {
		return data
	}
	key, _ := base64.StdEncoding.DecodeString(encryption.Key)
	switch encryption.Algorithm {
	case "aes-256-gcm":
		block, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(block)
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			log.Fatal("Nonce generation failed: ", err)
		}
		encrypted := aesGCM.Seal(nonce, nonce, data, nil)
		return encrypted
	case "chacha20-poly1305":
		chachaKey, _ := chacha20poly1305.NewKeyFromBytes(key)
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			log.Fatal("Nonce generation failed: ", err)
		}
		encrypted := chacha20poly1305.Seal(nonce, chachaKey, data, nil)
		return encrypted
	default:
		return data
	}
}
