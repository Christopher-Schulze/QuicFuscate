package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

// FakeTLSConfig erzeugt eine TLS-Konfiguration mit Fake-Zertifikat
func FakeTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quicsand"},
	}
}

// DialWithFakeTLS stellt eine QUIC-Verbindung mit Fake TLS her
func DialWithFakeTLS(addr string) (quic.Session, error) {
	tlsConfig := FakeTLSConfig()
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIncomingStreams:   1000,
	}

	session, err := quic.DialAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC connection failed: %v", err)
	}

	return session, nil
}
