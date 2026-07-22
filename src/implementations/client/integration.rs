//! Integration test module for client-server communication.
//!
//! This module provides utilities for testing the full packet flow
//! between client and server without requiring root privileges.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Mock server for integration testing.
///
/// Implements a simple echo server that receives QUIC packets
/// and echoes them back through the connection.
pub struct MockServer {
    bind_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    packets_received: Arc<AtomicU64>,
    packets_sent: Arc<AtomicU64>,
}

impl MockServer {
    /// Create a new mock server bound to the given address.
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            shutdown: Arc::new(AtomicBool::new(false)),
            packets_received: Arc::new(AtomicU64::new(0)),
            packets_sent: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get packets received count.
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Get packets sent count.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Run the echo server on a socket that is already bound and ready.
    pub async fn run_echo(&self, socket: UdpSocket) -> std::io::Result<()> {
        log::info!("Mock server listening on {}", socket.local_addr()?);

        let mut buf = vec![0u8; 65535];

        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(100),
                socket.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, src))) => {
                    self.packets_received.fetch_add(1, Ordering::Relaxed);
                    log::debug!("Received {} bytes from {}", len, src);

                    // Echo back
                    if socket.send_to(&buf[..len], src).await.is_ok() {
                        self.packets_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("Recv error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        log::info!("Mock server shutdown");
        Ok(())
    }
}

/// Test client for integration testing.
pub struct TestClient {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
}

impl TestClient {
    /// Create a new test client.
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            local_addr: "0.0.0.0:0".parse().unwrap(),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get packets sent count.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get packets received count.
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Send a test packet and wait for echo response.
    pub async fn send_and_receive(&self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let socket = UdpSocket::bind(self.local_addr).await?;
        socket.connect(self.remote_addr).await?;

        // Send
        socket.send(data).await?;
        self.packets_sent.fetch_add(1, Ordering::Relaxed);

        // Receive with timeout
        let mut buf = vec![0u8; 65535];
        match tokio::time::timeout(tokio::time::Duration::from_secs(1), socket.recv(&mut buf)).await
        {
            Ok(Ok(len)) => {
                self.packets_received.fetch_add(1, Ordering::Relaxed);
                Ok(buf[..len].to_vec())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "receive timeout")),
        }
    }
}

/// Test harness for running client-server tests.
pub struct TestHarness {
    server: MockServer,
    server_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl TestHarness {
    /// Create a new test harness.
    pub async fn new() -> std::io::Result<Self> {
        let server = MockServer::new(SocketAddr::from(([127, 0, 0, 1], 0)));

        Ok(Self { server, server_handle: None })
    }

    /// Start the server.
    pub async fn start(&mut self) -> std::io::Result<()> {
        let socket = UdpSocket::bind(self.server.bind_addr).await?;
        self.server.bind_addr = socket.local_addr()?;
        let shutdown = self.server.shutdown_signal();
        let packets_recv = self.server.packets_received.clone();
        let packets_sent = self.server.packets_sent.clone();
        let bind_addr = self.server.bind_addr;

        self.server_handle = Some(tokio::spawn(async move {
            let server =
                MockServer { bind_addr, shutdown, packets_received: packets_recv, packets_sent };
            server.run_echo(socket).await
        }));
        Ok(())
    }

    /// Create a test client.
    pub fn client(&self) -> TestClient {
        TestClient::new(self.server.bind_addr)
    }

    /// Stop the server.
    pub async fn stop(&mut self) {
        self.server.shutdown();
        if let Some(handle) = self.server_handle.take() {
            let _ = handle.await;
        }
    }

    /// Get server stats.
    pub fn server_stats(&self) -> (u64, u64) {
        (self.server.packets_received(), self.server.packets_sent())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_server_echo() {
        let mut harness = TestHarness::new().await.unwrap();
        harness.start().await.unwrap();

        let client = harness.client();

        // Send test data
        let test_data = b"Hello, QuicFuscate!";
        let response = client.send_and_receive(test_data).await.unwrap();

        assert_eq!(response, test_data);
        assert_eq!(client.packets_sent(), 1);
        assert_eq!(client.packets_received(), 1);

        harness.stop().await;

        let (recv, sent) = harness.server_stats();
        assert_eq!(recv, 1);
        assert_eq!(sent, 1);
    }

    #[tokio::test]
    async fn test_multiple_packets() {
        let mut harness = TestHarness::new().await.unwrap();
        harness.start().await.unwrap();

        let client = harness.client();

        // Send multiple packets
        for i in 0..10 {
            let data = format!("Packet {}", i);
            let response = client.send_and_receive(data.as_bytes()).await.unwrap();
            assert_eq!(response, data.as_bytes());
        }

        assert_eq!(client.packets_sent(), 10);
        assert_eq!(client.packets_received(), 10);

        harness.stop().await;
    }

    #[tokio::test]
    async fn test_large_packet() {
        let mut harness = TestHarness::new().await.unwrap();
        harness.start().await.unwrap();

        let client = harness.client();

        // Send large packet (MTU size)
        let test_data: Vec<u8> = (0..1400).map(|i| (i % 256) as u8).collect();
        let response = client.send_and_receive(&test_data).await.unwrap();

        assert_eq!(response, test_data);

        harness.stop().await;
    }
}
