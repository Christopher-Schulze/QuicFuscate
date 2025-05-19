// Package main contains the entry point for the StealthQUIC-VPN server
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"github.com/songgao/water"
)


func main() {
	// Flag configuration
	addrFlag := flag.String("addr", "0.0.0.0:4242", "Server listen address")
	caCertFlag := flag.String("ca-cert", "", "Path to CA certificate for client authentication")
	metricsAddrFlag := flag.String("metrics-addr", ":8080", "Metrics endpoint address")

	flag.Parse()

	// Use flags or environment variables
	addr := os.Getenv("QUIC_ADDR")
	if addr == "" {
		addr = *addrFlag
	}
	caCertPath := os.Getenv("QUIC_CA_CERT")
	if caCertPath == "" {
		caCertPath = *caCertFlag
	}

	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}

	// Setup TUN interface
	iface, err := SetupTUN()
	if err != nil {
		log.Fatalf("Failed to setup TUN interface: %v", err)
	}

	// Start QUIC listener
	listener, err := quic.Listen(udpListener, generateTLSConfig(caCertPath), generateQUICConfig())
	if err != nil {
		log.Fatalf("Fehler beim Starten des QUIC-Listeners: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Fehler beim Schließen des Listeners: %v", err)
		}
	}()

	// Start metrics server
	go startMetricsServer(*metricsAddrFlag)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	var wg sync.WaitGroup

	for {
		select {
		case <-interrupt:
			log.Println("SIGINT empfangen, warte auf laufende Verbindungen...")
			wg.Wait()
			log.Println("Shutdown abgeschlossen.")
			return
		default:
			conn, err := listener.Accept(context.Background())
			if err != nil {
				log.Printf("Fehler beim Akzeptieren einer Verbindung: %v", err)
				continue
			}
			wg.Add(1)
			go handleConnection(conn, &wg, iface)
		}
	}
}

func handleConnection(conn quic.Connection, wg *sync.WaitGroup, iface *water.Interface) {
	defer wg.Done()
	defer func() {
		if err := conn.CloseWithError(0, "Server schließt Verbindung"); err != nil {
			log.Printf("Fehler beim Schließen der Verbindung: %v", err)
		}
	}()

	// Start TUN traffic handler
	go HandleTUNTraffic(context.Background(), iface, conn)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Fehler beim Akzeptieren eines Streams: %v", err)
			return
		}
		go func(s quic.Stream) {
			defer func() {
				if err := s.Close(); err != nil {
					log.Printf("Fehler beim Schließen des Streams: %v", err)
				}
			}()
			buffer := make([]byte, 4096)
			for {
				n, err := s.Read(buffer)
				if err != nil {
					if err != io.EOF {
						log.Printf("Fehler beim Lesen vom Stream: %v", err)
					}
					break
				}
				message := string(buffer[:n])
				log.Printf("Empfangen von %s: %s", conn.RemoteAddr(), message)
				if _, err := s.Write([]byte("Hello from server")); err != nil {
					log.Printf("Fehler beim Schreiben in den Stream: %v", err)
					break
				}
			}
		}(stream)
	}
}

func generateTLSConfig(caCertPath string) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // Using a stronger key size (2048 bits)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	// Load CA certificate for client authentication
	if caCertPath == "" {
		log.Fatal("QUIC_CA_CERT environment variable not set")
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
		},
		MinVersion: tls.VersionTLS12,
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{
		Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			filename := fmt.Sprintf("server_%s.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Printf("Failed to create qlog file %s: %v\n", filename, err)
				return nil
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return qlog.NewConnectionTracer(f, p, connID)
		},
	}
}

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
