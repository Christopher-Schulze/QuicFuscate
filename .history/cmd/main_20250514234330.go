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

const addr = "0.0.0.0:4242"

func main() {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	var wg sync.WaitGroup

	for {
		select {
		case <-interrupt:
			wg.Wait()
			return
		default:
			conn, err := listener.Accept(context.Background())
			if err != nil {
				panic(err)
			}
			wg.Add(1)
			go handleConnection(conn, &wg)
		}
	}
}

func handleConnection(conn quic.Connection, wg *sync.WaitGroup) {
	defer wg.Done()
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	buffer := make([]byte, 1024)
	for {
		n, err := stream.Read(buffer)
		if err != nil {
			break
		}
		message := string(buffer[:n])
		println("Received:", message)
		if _, err := stream.Write([]byte("Hello from server")); err != nil {
			panic(err)
		}
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