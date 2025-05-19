package main

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
)

// startKeepaliveTicker sends periodic keepalive signals
func startKeepaliveTicker(ctx context.Context, conn quic.Connection, interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send keepalive signal
			stream, err := conn.OpenStream()
			if err != nil {
				log.Printf("Failed to open stream for keepalive: %v", err)
				continue
			}
			if _, err := stream.Write([]byte("keepalive")); err != nil {
				log.Printf("Failed to send keepalive: %v", err)
			}
			stream.Close()
		}
	}
}
