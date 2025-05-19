// Package main contains TUN interface handling for StealthQUIC-VPN
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
	"github.com/lucas-clemente/quic-go"
	"github.com/lajosbencz/gos"
	"github.com/xtaci/tetrys"
	"gopkg.in/yaml.v2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"encoding/base64"
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

// HandleTUNTraffic reads from TUN, applies FEC and encryption, then sends to QUIC
func HandleTUNTraffic(ctx context.Context, iface *water.Interface, quicConn quic.Connection, fecEncoder *fecEncoder, tetrysEncoder *tetrysEncoder, encryptionConfig EncryptionConfig) {
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

			// Apply encryption
			encrypted := ApplyEncryption(encoded, encryptionConfig)
			
			// Create new QUIC stream for TUN traffic
			stream, err := quicConn.OpenStream()
			if err != nil {
				log.Printf("Failed to open QUIC stream: %v", err)
				continue
			}

			// Write encrypted data to QUIC stream
			if _, err := stream.Write(encrypted); err != nil {
				log.Printf("Failed to write to QUIC stream: %v", err)
			}

			// Close stream after writing
			if err := stream.Close(); err != nil {
				log.Printf("Failed to close QUIC stream: %v", err)
			}
		}
	}
}

// HandleQUICStream reads from QUIC, decrypts and writes to TUN
func HandleQUICStream(ctx context.Context, stream quic.Stream, iface *water.Interface, encryptionConfig EncryptionConfig) {
	buffer := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := stream.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("QUIC stream read error: %v", err)
				}
				break
			}

			// Apply decryption
			decrypted, err := ApplyDecryption(buffer[:n], encryptionConfig)
			if err != nil {
				log.Printf("Decryption failed: %v", err)
				continue
			}

			// Write to TUN interface
			if _, err := iface.Write(decrypted); err != nil {
				log.Printf("Failed to write to TUN: %v", err)
			}
		}
	}
}

// ApplyEncryption encrypts data using configured algorithm
func ApplyEncryption(data []byte, encryptionConfig EncryptionConfig) []byte {
	if !encryptionConfig.Enabled {
		return data
	}
	
	key, _ := base64.StdEncoding.DecodeString(encryptionConfig.Key)
	switch encryptionConfig.Algorithm {
	case "aes-256-gcm":
		block, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(block)
		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			log.Fatal("Nonce generation failed: ", err)
		}
		encrypted := aesGCM.Seal(nonce, nonce, data, nil)
		return encrypted
	case "chacha20-poly1305":
		chachaKey, _ := chacha20poly1305.NewKeyFromBytes(key)
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			log.Fatal("Nonce generation failed: ", err)
		}
		encrypted := chacha20poly1305.Seal(nonce, chachaKey, data, nil)
		return encrypted
	default:
		return data
	}
}

// ApplyDecryption decrypts data using configured algorithm
func ApplyDecryption(data []byte, encryptionConfig EncryptionConfig) ([]byte, error) {
	if !encryptionConfig.Enabled {
		return data, nil
	}
	
	key, _ := base64.StdEncoding.DecodeString(encryptionConfig.Key)
	switch encryptionConfig.Algorithm {
	case "aes-256-gcm":
		block, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(block)
		nonceSize := aesGCM.NonceSize()
		if len(data) < nonceSize {
			return nil, fmt.Errorf("data too short for AES-256-GCM")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("AES decryption failed: %v", err)
		}
		return decrypted, nil
	case "chacha20-poly1305":
		if len(data) < chacha20poly1305.NonceSize {
			return nil, fmt.Errorf("data too short for ChaCha20-Poly1305")
		}
		nonce, ciphertext := data[:chacha20poly1305.NonceSize], data[chacha20poly1305.NonceSize:]
		chachaKey, _ := chacha20poly1305.NewKeyFromBytes(key)
		decrypted, err := chacha20poly1305.Open(nonce, chachaKey, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("ChaCha20-Poly1305 decryption failed: %v", err)
		}
		return decrypted, nil
	default:
		return data, nil
	}
}
