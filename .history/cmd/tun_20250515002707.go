// Package main contains TUN interface handling for StealthQUIC-VPN
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

// SetupTUN creates and configures a TUN interface
func SetupTUN() (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN interface: %w", err)
	}

	log.Printf("TUN interface %s created", iface.Name())

	// Configure interface (basic example - would need proper IP setup)
	if err := iface.Configure(); err != nil {
		return nil, fmt.Errorf("failed to configure TUN interface: %w", err)
	}

	return iface, nil
}

// HandleTUNTraffic reads from TUN and sends to QUIC
func HandleTUNTraffic(ctx context.Context, iface *water.Interface, quicConn quic.Connection) {
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

			// Create new QUIC stream for TUN traffic
			stream, err := quicConn.OpenStream()
			if err != nil {
				log.Printf("Failed to open QUIC stream: %v", err)
				continue
			}

			// Write TUN data to QUIC stream
			if _, err := stream.Write(buffer[:n]); err != nil {
				log.Printf("Failed to write to QUIC stream: %v", err)
			}

			// Close stream after writing
			if err := stream.Close(); err != nil {
				log.Printf("Failed to close QUIC stream: %v", err)
			}
		}
	}
}
