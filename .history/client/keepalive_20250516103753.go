package main

import (
	"context"
	"fmt"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

// SendKeepalive sendet ein Keepalive-Paket an den Server
func SendKeepalive(session quic.Session, config *ClientConfig) error {
	stream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("failed to open keepalive stream: %v", err)
	}
	defer stream.Close()

	// Keepalive-Nachricht senden
	_, err = stream.Write([]byte("KEEPALIVE"))
	if err != nil {
		return fmt.Errorf("failed to send keepalive: %v", err)
	}

	// Kontext für Timeout erstellen
	ctx, cancel := context.WithTimeout(context.Background(), config.Keepalive.Timeout)
	defer cancel()

	// Auf Antwort warten
	buffer := make([]byte, 1024)
	n, err := stream.Read(buffer)
	if err != nil {
		return fmt.Errorf("keepalive response failed: %v", err)
	}

	response := string(buffer[:n])
	if response != "ALIVE" {
		return fmt.Errorf("unexpected keepalive response: %s", response)
	}

	return nil
}
