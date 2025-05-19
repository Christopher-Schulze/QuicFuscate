// Package main contains the entry point for the StealthQUIC-VPN server
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
	"gopkg.in/yaml.v2"
	"QuicSand/tetrys"
	"golang.org/x/crypto/chacha20poly1305"
	"crypto/rand"
	"io"
	"encoding/base64"
	"net/http"
)

// Config holds server configuration
type Config struct {
	Server struct {
		Address string `yaml:"address"`
		Cert    string `yaml:"cert"`
		Key     string `yaml:"key"`
	} `yaml:"server"`
	Keepalive struct {
		Interval int `yaml:"interval"`
	} `yaml:"keepalive"`
	Encryption EncryptionConfig `yaml:"encryption"`
}

// EncryptionConfig holds encryption settings
type EncryptionConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Algorithm string `yaml:"algorithm"`
	Key       string `yaml:"key"`
}

// loadConfig loads configuration from YAML file
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

func main() {
	// Load configuration
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", config.Server.Address)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}

	// Setup TUN interface with adaptive MTU
	iface, err := SetupTUN(udpListener)
	if err != nil {
		log.Fatalf("Failed to setup TUN interface: %v", err)
	}

	// Generate TLS config with client certificate authentication
	tlsConfig, err := generateTLSConfig(config.Server.Cert, config.Server.Key, "ca.crt")
	if err != nil {
		log.Fatalf("Failed to generate TLS config: %v", err)
	}

	// Start QUIC listener
	quicListener, err := quic.ListenAddr(udpListener, &quic.Config{
		TLSConfig: tlsConfig,
	})
	if err != nil {
		log.Fatalf("Failed to start QUIC listener: %v", err)
	}
	defer quicListener.Close()

	// Start metrics server
	go startMetricsServer(":8080")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	var wg sync.WaitGroup

	// Main connection loop
	for {
		select {
		case <-interrupt:
			log.Println("Shutting down server...")
			wg.Wait()
			return
		default:
			conn, err := quicListener.Accept(context.Background())
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}
			wg.Add(1)
			go handleConnection(conn, &wg, iface, config.Encryption)
		}
	}
}

// generateTLSConfig creates TLS config with server certificate and client authentication
func generateTLSConfig(certPath, keyPath, caCertPath string) (*tls.Config, error) {
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	// Load CA certificate for client authentication
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode CA certificate")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"quic-echo-example"},
	}, nil
}

// handleConnection handles a single QUIC connection
func handleConnection(conn quic.Connection, wg *sync.WaitGroup, iface *water.Interface, encryptionConfig EncryptionConfig) {
	defer wg.Done()
	defer func() {
		if err := conn.CloseWithError(0, "Server closing connection"); err != nil {
			log.Printf("Failed to close connection: %v", err)
		}
	}()

	// Create Tetrys encoder
	tetrysEncoder, err := newTetrysEncoder()
	if err != nil {
		log.Printf("Failed to create Tetrys encoder: %v", err)
		return
	}

	// Start TUN traffic handler
	go HandleTUNTraffic(context.Background(), iface, conn, tetrysEncoder, encryptionConfig)

	// Start keepalive ticker
	go startKeepaliveTicker(context.Background(), conn, config.Keepalive.Interval)

	// Accept incoming streams
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Failed to accept stream: %v", err)
			break
		}
		go func(s quic.Stream) {
			defer func() {
				if err := s.Close(); err != nil {
					log.Printf("Failed to close stream: %v", err)
				}
			}()
			buffer := make([]byte, 65535)
			for {
				n, err := s.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Stream read error: %v", err)
					}
					break
				}
				// Apply decryption
				decrypted, err := ApplyDecryption(buffer[:n], encryptionConfig)
				if err != nil {
					log.Printf("Decryption failed: %v", err)
					continue
				}
				// Write to TUN interface
				if _, err := iface.Write(decrypted); err != nil {
					log.Printf("Failed to write to TUN: %v", err)
				}
			}
		}(stream)
	}
}

// SetupTUN creates and configures a TUN interface with adaptive MTU
func SetupTUN(conn net.Conn) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	// Detect optimal MTU
	mtu, err := adaptiveMTUDetect(conn)
	if err != nil {
		log.Printf("Failed to detect MTU: %v", err)
		mtu = 1400
	}

	log.Printf("TUN interface %s created with MTU %d", iface.Name(), mtu)

	return iface, nil
}

// startMetricsServer starts the health check endpoint
func startMetricsServer(addr string) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	log.Printf("Starting metrics server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Metrics server failed: %v", err)
	}
}

// startKeepaliveTicker sends periodic keepalive messages
func startKeepaliveTicker(ctx context.Context, conn quic.Connection, interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := SendKeepalive(conn); err != nil {
				log.Printf("Keepalive failed: %v", err)
				return
			}
		}
	}
}

// SendKeepalive sends a keepalive message over QUIC
func SendKeepalive(conn quic.Connection) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()
	_, err = stream.Write([]byte("keepalive"))
	return err
}

// adaptiveMTUDetect implements MTU detection logic
func adaptiveMTUDetect(conn net.Conn) (int, error) {
	// Implementation would use network path MTU discovery
	return 1400, nil
}


// newTetrysEncoder creates a new Tetrys encoder
func newTetrysEncoder() (*tetrysEncoder, error) {
	return &tetrysEncoder{}, nil
}

// HandleTUNTraffic reads from TUN, applies FEC and encryption, then sends to QUIC
func HandleTUNTraffic(ctx context.Context, iface *water.Interface, quicConn quic.Connection, tetrysEncoder *tetrysEncoder, encryptionConfig EncryptionConfig) {
	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := iface.Read(buffer)
			if err != nil {
				log.Printf("TUN read error: %v", err)
				continue
			}

			// Apply Tetrys encoding
			encoded, err := tetrysEncoder.encode(buffer[:n])
			if err != nil {
				log.Printf("Tetrys encoding error: %v", err)
				continue
			}

			// Apply encryption
			encrypted := ApplyEncryption(encoded, encryptionConfig)
			
			// Create new QUIC stream
			stream, err := quicConn.OpenStream()
			if err != nil {
				log.Printf("Failed to open QUIC stream: %v", err)
				continue
			}

			// Write encrypted data
			if _, err := stream.Write(encrypted); err != nil {
				log.Printf("Failed to write to QUIC stream: %v", err)
			}

			// Close stream
			if err := stream.Close(); err != nil {
				log.Printf("Failed to close QUIC stream: %v", err)
			}
		}
	}
}

// ApplyEncryption encrypts data using configured algorithm
func ApplyEncryption(data []byte, encryptionConfig EncryptionConfig) []byte {
	if !encryptionConfig.Enabled {
		return data
	}
	
	key, _ := base64.StdEncoding.DecodeString(encryptionConfig.Key)
	switch encryptionConfig.Algorithm {
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

// ApplyDecryption decrypts data using configured algorithm
func ApplyDecryption(data []byte, encryptionConfig EncryptionConfig) ([]byte, error) {
	if !encryptionConfig.Enabled {
		return data, nil
	}
	
	key, _ := base64.StdEncoding.DecodeString(encryptionConfig.Key)
	switch encryptionConfig.Algorithm {
	case "aes-256-gcm":
		block, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(block)
		nonceSize := aesGCM.NonceSize()
		if len(data) < nonceSize {
			return nil, fmt.Errorf("data too short for AES-256-GCM")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("AES decryption failed: %v", err)
		}
		return decrypted, nil
	case "chacha20-poly1305":
		if len(data) < chacha20poly1305.NonceSize {
			return nil, fmt.Errorf("data too short for ChaCha20-Poly1305")
		}
		nonce, ciphertext := data[:chacha20poly1305.NonceSize], data[chacha20poly1305.NonceSize:]
		chachaKey, _ := chacha20poly1305.NewKeyFromBytes(key)
		decrypted, err := chacha20poly1305.Open(nonce, chachaKey, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("ChaCha20-Poly1305 decryption failed: %v", err)
		}
		return decrypted, nil
	default:
		return data, nil
	}
}



// Tetrys encoder implementation
type tetrysEncoder struct{}

func (t *tetrysEncoder) encode(data []byte) ([]byte, error) {
	// Implementation would apply Tetrys encoding
	return data, nil
}
