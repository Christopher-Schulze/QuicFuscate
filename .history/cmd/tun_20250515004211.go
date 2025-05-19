// Package main contains TUN interface handling for StealthQUIC-VPN
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

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
		// Use default MTU if detection fails
		mtu = 1400
	}

	log.Printf("TUN interface %s created with MTU %d", iface.Name(), mtu)

	return iface, nil
}

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
)

// HandleTUNTraffic reads from TUN, applies FEC, and sends to QUIC
func HandleTUNTraffic(ctx context.Context, iface *water.Interface, quicConn quic.Connection, fecEncoder *fecEncoder, tetrysEncoder *tetrysEncoder) {
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

			// Apply FEC encoding
			encoded, err := fecEncoder.encode(buffer[:n])
			if err != nil {
				log.Printf("FEC encoding error: %v", err)
				continue
			}

			// Create new QUIC stream for TUN traffic
			stream, err := quicConn.OpenStream()
			if err != nil {
				log.Printf("Failed to open QUIC stream: %v", err)
				continue
			}

			// Write encoded data to QUIC stream
			if _, err := stream.Write(encoded); err != nil {
				log.Printf("Failed to write to QUIC stream: %v", err)
			}

			// Close stream after writing
			if err := stream.Close(); err != nil {
				log.Printf("Failed to close QUIC stream: %v", err)
			}
		}
	}
}
