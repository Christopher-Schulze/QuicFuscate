package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"os/signal"
	"sync"
	"fmt"
	// "encoding/hex" // Entfernt, da nicht verwendet
	"io"
	"log"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

const addr = os.Getenv("QUIC_ADDR")
if addr == "" {
    addr = "0.0.0.0:4242"
}

func main() {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		log.Fatalf("Fehler beim Starten des QUIC-Listeners: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Fehler beim Schließen des Listeners: %v", err)
		}
	}()

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
			go handleConnection(conn, &wg)
		}
	}
}

func handleConnection(conn quic.Connection, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		if err := conn.CloseWithError(0, "Server schließt Verbindung"); err != nil {
			log.Printf("Fehler beim Schließen der Verbindung: %v", err)
		}
	}()
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

func generateTLSConfig() *tls.Config {
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
			return qlog.NewConnectionTracer(struct {
				io.Writer
				io.Closer
			}{
				Writer: f,
				Closer: f,
			}, p, connID)
		},
	}
}
