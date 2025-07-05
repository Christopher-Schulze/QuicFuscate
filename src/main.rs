use crate::core::QuicFuscateConnection;
use crate::fec::FecMode;
use crate::stealth::StealthConfig;
use crate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, default_value = "windows")]
        os: String,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,


        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Disable DNS over HTTPS
        #[clap(long)]
        disable_doh: bool,

        /// Disable domain fronting
        #[clap(long)]
        disable_fronting: bool,

        /// Disable XOR obfuscation
        #[clap(long)]
        disable_xor: bool,

        /// Disable HTTP/3 masquerading
        #[clap(long)]
        disable_http3: bool,
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

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, default_value = "windows")]
        os: String,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,


        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Disable DNS over HTTPS
        #[clap(long)]
        disable_doh: bool,

        /// Disable domain fronting
        #[clap(long)]
        disable_fronting: bool,

        /// Disable XOR obfuscation
        #[clap(long)]
        disable_xor: bool,

        /// Disable HTTP/3 masquerading
        #[clap(long)]
        disable_http3: bool,
    },
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    crate::telemetry::serve("0.0.0.0:9898");
    let cli = Cli::parse();

    match &cli.command {
        Commands::Client {
            server_addr,
            url,
            profile,
            os,
            profile_seq,
            profile_interval,
            fec_mode,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
        } => {
            let browser = profile.parse().unwrap_or(BrowserProfile::Chrome);
            let os_profile = os.parse().unwrap_or(OsProfile::Windows);
            run_client(
                server_addr,
                url,
                browser,
                os_profile,
                profile_seq,
                *profile_interval,
                *fec_mode,
                *disable_doh,
                *disable_fronting,
                *disable_xor,
                *disable_http3,
            )
            .await?;
        }
        Commands::Server {
            listen,
            cert,
            key,
            profile,
            os,
            profile_seq,
            profile_interval,
            fec_mode,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
        } => {
            let browser = profile.parse().unwrap_or(BrowserProfile::Chrome);
            let os_profile = os.parse().unwrap_or(OsProfile::Windows);
            run_server(
                listen,
                cert,
                key,
                browser,
                os_profile,
                profile_seq,
                *profile_interval,
                *fec_mode,
                *disable_doh,
                *disable_fronting,
                *disable_xor,
                *disable_http3,
            )
            .await?;
        }
    }

    Ok(())
}

fn parse_profile_entry(entry: &str, default_os: OsProfile) -> Option<FingerprintProfile> {
    let parts: Vec<&str> = entry.split('@').collect();
    let browser_part = parts.get(0)?;
    let browser = browser_part.parse().ok()?;
    let os = if let Some(os_part) = parts.get(1) {
        os_part.parse().ok()?
    } else {
        default_os
    };
    Some(FingerprintProfile::new(browser, os))
}

async fn run_client(
    server_addr_str: &str,
    url: &str,
    profile: BrowserProfile,
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: FecMode,
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
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

    let url_parsed =
        url::Url::parse(url).unwrap_or_else(|_| url::Url::parse("https://example.com/").unwrap());
    let mut stealth_config = StealthConfig::default();
    stealth_config.browser_profile = profile;
    stealth_config.os_profile = os;
    stealth_config.enable_doh = !disable_doh;
    stealth_config.enable_domain_fronting = !disable_fronting;
    stealth_config.enable_xor_obfuscation = !disable_xor;
    stealth_config.enable_http3_masquerading = !disable_http3;

    let host = url_parsed.host_str().unwrap_or("example.com");
    let mut conn =
        QuicFuscateConnection::new_client(host, server_addr, config, stealth_config, fec_mode)
            .expect("failed to create client connection");

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq
            .iter()
            .filter_map(|s| parse_profile_entry(s, os))
            .collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.len() > 1 {
        let sm = conn.stealth_manager();
        sm.start_profile_rotation(profiles, std::time::Duration::from_secs(profile_interval));
    }

    let mut buf = [0; 65535];
    let mut out = [0; 65535];

    // Send initial packet
    if let Ok(len) = conn.send(&mut out) {
        if len > 0 {
            socket.send(&out[..len])?;
            info!("Sent initial packet of size {}", len);
        }
    }

    let mut request_sent = false;

    loop {
        // Process incoming packets
        match socket.recv(&mut buf) {
            Ok(len) => {
                let _ = conn.recv(&mut buf[..len]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                error!("Failed to read from socket: {}", e);
                break;
            }
        }

        if conn.conn.is_established() && !request_sent {
            if let Err(e) = conn.send_http3_request(url_parsed.path()) {
                warn!("HTTP/3 request failed: {:?}", e);
            } else {
                request_sent = true;
            }
        }

        if let Err(e) = conn.poll_http3() {
            warn!("HTTP/3 error: {:?}", e);
        }

        loop {
            match conn.send(&mut out) {
                Ok(len) if len > 0 => {
                    socket.send(&out[..len])?;
                }
                Ok(_) => break,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("Send failed: {:?}", e);
                    break;
                }
            }
        }

        conn.update_state();
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
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: FecMode,
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
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
    let stealth_config = Arc::new(Mutex::new(StealthConfig::default()));
    {
        let mut sc = stealth_config.lock().unwrap();
        sc.browser_profile = profile;
        sc.os_profile = os;
        sc.enable_doh = !disable_doh;
        sc.enable_domain_fronting = !disable_fronting;
        sc.enable_xor_obfuscation = !disable_xor;
        sc.enable_http3_masquerading = !disable_http3;
    }

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq.iter().filter_map(|s| parse_profile_entry(s, os)).collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.len() > 1 {
        let cfg = stealth_config.clone();
        tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(profile_interval)).await;
                idx = (idx + 1) % profiles.len();
                let mut guard = cfg.lock().unwrap();
                guard.browser_profile = profiles[idx].browser;
                guard.os_profile = profiles[idx].os;
            }
        });
    }

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                info!("Received {} bytes from {}", len, from);
                let client_conn = clients.entry(from).or_insert_with(|| {
                    info!("New client connected: {}", from);
                    let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
                    let cfg = stealth_config.lock().unwrap().clone();
                    QuicFuscateConnection::new_server(
                        &scid,
                        None,
                        socket.local_addr().unwrap(),
                        from,
                        config.clone(),
                        cfg,
                        fec_mode,
                    )
                    .expect("failed to create server connection")
                });

                if let Err(e) = client_conn.recv(&mut buf[..len]) {
                    error!("QUIC recv failed: {:?}", e);
                    continue;
                }

                if let Err(e) = client_conn.poll_http3() {
                    warn!("HTTP/3 error: {:?}", e);
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
            loop {
                match conn.send(&mut out) {
                    Ok(len) if len > 0 => {
                        if let Err(e) = socket.send_to(&out[..len], addr) {
                            error!("Failed to send packet to {}: {}", addr, e);
                        }
                    }
                    Ok(_) => break,
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        error!("Send failed to {}: {:?}", addr, e);
                        break;
                    }
                }
            }
            conn.update_state();
            conn.conn.on_timeout();
        }

        // Clean up closed connections
        clients.retain(|_, conn| !conn.conn.is_closed());

        // Sleep to avoid busy-looping
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok(())
}