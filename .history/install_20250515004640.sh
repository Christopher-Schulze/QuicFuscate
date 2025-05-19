#!/bin/bash

# QuicSand-VPN Server Installer for Linux

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

# Install dependencies
apt-get update
apt-get install -y golang-go

# Build the server
go build -o quicsand-vpn cmd/main.go cmd/tun.go fec.go tetrys.go fake_tls.go config.go mtu_detection.go keepalive.go

# Create configuration directory
mkdir -p /etc/quicsand-vpn

# Copy configuration files
cp config.yaml /etc/quicsand-vpn/
cp ca.crt /etc/quicsand-vpn/

# Create systemd service file
cat > /etc/systemd/system/quicsand-vpn.service << EOF
[Unit]
Description=QuicSand-VPN Server
After=network.target

[Service]
ExecStart=/usr/local/bin/quicsand-vpn -config /etc/quicsand-vpn/config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Move binary to system path
mv quicsand-vpn /usr/local/bin/

# Enable and start service
systemctl enable quicsand-vpn.service
systemctl start quicsand-vpn.service

echo "QuicSand-VPN server installed successfully"
