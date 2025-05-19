#!/bin/bash

# QuicSand-VPN Server Build Script

# Build the server
go build -o quicsand-vpn cmd/main.go cmd/tun.go fec.go tetrys.go fake_tls.go config.go mtu_detection.go keepalive.go

echo "QuicSand-VPN server binary created successfully"
