use crate::core::QuicFuscateConnection;
use crate::stealth::StealthConfig;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the client
    Client {
        /// The server address to connect to
        #[clap(required = true)]
        server_addr: String,

        /// The URL to request
        #[clap(short, long, default_value = "https://example.com")]
        url: String,

        /// Browser fingerprint profile (chrome, firefox, opera, brave)
        #[clap(long, default_value = "chrome")]
        profile: String,
    },
    /// Runs the server
    Server {
        /// The address to listen on
        #[clap(short, long, default_value = "127.0.0.1:4433")]
        listen: String,

        /// Path to the certificate file
        #[clap(short, long, required = true)]
        cert: PathBuf,

        /// Path to the private key file
        #[clap(short, long, required = true)]
        key: PathBuf,

        /// Browser fingerprint profile used for connections
        #[clap(long, default_value = "chrome")]
        profile: String,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Client {
            server_addr,
            url,
            profile,
        } => {
            let browser = profile.parse().unwrap_or(BrowserProfile::Chrome);
            run_client(server_addr, url, browser).await?;
        }
        Commands::Server {
            listen,
            cert,
            key,
            profile,
        } => {
            let browser = profile.parse().unwrap_or(BrowserProfile::Chrome);
            run_server(listen, cert, key, browser).await?;
        }
    }

    Ok(())
}

async fn run_client(
    server_addr_str: &str,
    url: &str,
    profile: BrowserProfile,
) -> std::io::Result<()> {
    let server_addr = server_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Server address not found")
    })?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;
    socket.set_nonblocking(true)?;

    info!("Client connecting to {}", server_addr);

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .set_application_protos(b"\x0ahq-interop\x05h3-29\x05h3-28\x05h3-27\x08http/0.9")
        .unwrap();
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(1460);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.verify_peer(false); // In a real app, you should verify the server cert.

    let mut stealth_config = StealthConfig::default();
    stealth_config.browser_profile = profile;
    let mut conn = QuicFuscateConnection::new_client(
        "example.com",
        server_addr,
        config,
        StealthConfig::default(),
    )
    .expect("failed to create client connection");

    let mut buf = [0; 65535];
    let mut out = [0; 1460];

    // Send initial packet
    if let Some((len, _)) = conn.conn.send(&mut out) {
        socket.send(&out[..len])?;
        info!("Sent initial packet of size {}", len);
    }

    loop {
        // Process incoming packets
        match socket.recv(&mut buf) {
            Ok(len) => {
                let _ = conn
                    .conn
                    .recv(&mut buf[..len], quiche::RecvInfo { from: server_addr });
                info!("Received packet of size {}", len);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No packets to read, continue
            }
            Err(e) => {
                error!("Failed to read from socket: {}", e);
                break;
            }
        }

        // If connection is established, send a request
        if conn.conn.is_established() {
            let req = format!("GET {}\r\n", url);
            match conn.conn.stream_send(0, req.as_bytes(), true) {
                Ok(_) => info!("Sent request: {}", req.trim()),
                Err(quiche::Error::Done) => {}
                Err(e) => {
                    error!("Failed to send request: {:?}", e);
                    break;
                }
            }
        }

        // Send outgoing packets
        while let Some((len, _)) = conn.conn.send(&mut out) {
            socket.send(&out[..len])?;
            info!("Sent packet of size {}", len);
        }

        // Check for timeout
        conn.conn.on_timeout();

        // Sleep to avoid busy-looping
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok(())
}

async fn run_server(
    listen_addr: &str,
    cert_path: &PathBuf,
    key_path: &PathBuf,
    profile: BrowserProfile,
) -> std::io::Result<()> {
    let socket = std::net::UdpSocket::bind(listen_addr)?;
    socket.set_nonblocking(true)?;
    info!("Server listening on {}", listen_addr);

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key_path.to_str().unwrap())
        .unwrap();
    config
        .set_application_protos(b"\x0ahq-interop\x05h3-29\x05h3-28\x05h3-27\x08http/0.9")
        .unwrap();
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(1460);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    let mut clients = HashMap::new();
    let mut buf = [0; 65535];
    let mut out = [0; 1460];
    let mut stealth_config = StealthConfig::default();
    stealth_config.browser_profile = profile;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                info!("Received {} bytes from {}", len, from);
                let client_conn = clients.entry(from).or_insert_with(|| {
                    info!("New client connected: {}", from);
                    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
                    QuicFuscateConnection::new_server(
                        &scid,
                        None,
                        socket.local_addr().unwrap(),
                        from,
                        config.clone(),
                        stealth_config.clone(),
                    )
                    .expect("failed to create server connection")
                });

                let recv_info = quiche::RecvInfo { from };
                if let Err(e) = client_conn.conn.recv(&mut buf[..len], recv_info) {
                    error!("QUIC recv failed: {:?}", e);
                    continue;
                }

                // Process stream data
                if client_conn.conn.is_established() {
                    for stream_id in client_conn.conn.readable() {
                        let mut stream_buf = [0; 4096];
                        while let Ok((read, fin)) =
                            client_conn.conn.stream_recv(stream_id, &mut stream_buf)
                        {
                            let data = &stream_buf[..read];
                            info!(
                                "Received on stream {}: {} bytes, fin={}",
                                stream_id, read, fin
                            );
                            // Echo back the received data
                            if let Err(e) = client_conn.conn.stream_send(stream_id, data, fin) {
                                error!("Stream send failed: {:?}", e);
                            }
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No packets to read
            }
            Err(e) => {
                error!("Failed to read from socket: {}", e);
                break;
            }
        }

        // Send packets for all clients
        for (addr, conn) in clients.iter_mut() {
            while let Some((len, _)) = conn.conn.send(&mut out) {
                if let Err(e) = socket.send_to(&out[..len], addr) {
                    error!("Failed to send packet to {}: {}", addr, e);
                } else {
                    info!("Sent {} bytes to {}", len, addr);
                }
            }
            conn.conn.on_timeout();
        }

        // Clean up closed connections
        clients.retain(|_, conn| !conn.conn.is_closed());

        // Sleep to avoid busy-looping
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok(())
}
