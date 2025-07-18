use crate::app_config::AppConfig;
use crate::core::QuicFuscateConnection;
use crate::fec::{FecConfig, FecMode};
use crate::optimize::OptimizeConfig;
#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
use crate::stealth::StealthConfig;
use crate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};
use crate::telemetry;
use clap::{Parser, Subcommand, ValueEnum};
use log::{error, info, warn};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::signal;
use tokio::time;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    /// Enable verbose logging
    #[clap(short, long, global = true)]
    verbose: bool,
    /// Enable telemetry metrics
    #[clap(long, global = true)]
    telemetry: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the client
    Client {
        /// The remote server address to connect to
        #[clap(long, required = true)]
        remote: String,

        /// Local UDP address to bind
        #[clap(long, default_value = "0.0.0.0:0")]
        local: String,

        /// The URL to request
        #[clap(short, long, default_value = "https://example.com")]
        url: String,

        /// Browser fingerprint profile (chrome, firefox, opera, brave)
        #[clap(long, value_enum, default_value_t = BrowserProfile::Chrome)]
        profile: BrowserProfile,

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, value_enum, default_value_t = OsProfile::Windows)]
        os: OsProfile,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,

        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Memory pool capacity (number of blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,

        /// Memory pool block size in bytes
        #[clap(long, default_value_t = 4096)]
        pool_block: usize,

        /// Enable XDP acceleration if supported
        #[clap(long)]
        xdp: bool,

        /// Print live XDP statistics
        #[clap(long)]
        xdp_stats: bool,

        /// Path to a unified TOML configuration file
        #[clap(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Path to a TOML file with Adaptive FEC settings
        #[clap(long, value_name = "PATH")]
        fec_config: Option<PathBuf>,

        /// Custom DNS-over-HTTPS provider URL
        #[clap(long, default_value = "https://cloudflare-dns.com/dns-query")]
        doh_provider: String,

        /// Domain used for fronting (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        front_domain: Vec<String>,
        /// CA file for peer verification
        #[clap(long, value_name = "PATH")]
        ca_file: Option<PathBuf>,
        /// Disable uTLS and use regular TLS
        #[clap(long)]
        no_utls: bool,
        /// Show TLS debug information
        #[clap(long)]
        debug_tls: bool,
        /// List available browser fingerprints
        #[clap(long)]
        list_fingerprints: bool,
        /// Enable certificate validation when connecting to the server
        #[clap(long)]
        verify_peer: bool,

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
        #[clap(long, value_enum, default_value_t = BrowserProfile::Chrome)]
        profile: BrowserProfile,

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, value_enum, default_value_t = OsProfile::Windows)]
        os: OsProfile,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,

        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Memory pool capacity (number of blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,

        /// Memory pool block size in bytes
        #[clap(long, default_value_t = 4096)]
        pool_block: usize,

        /// Path to a unified TOML configuration file
        #[clap(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Path to a TOML file with Adaptive FEC settings
        #[clap(long, value_name = "PATH")]
        fec_config: Option<PathBuf>,

        /// Custom DNS-over-HTTPS provider URL
        #[clap(long, default_value = "https://cloudflare-dns.com/dns-query")]
        doh_provider: String,

        /// Domain used for fronting (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        front_domain: Vec<String>,

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
    let cli = Cli::parse();
    if cli.verbose {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();
    if cli.telemetry {
        telemetry::TELEMETRY_ENABLED.store(true, Ordering::Relaxed);
        crate::telemetry::serve("0.0.0.0:9898");
    }

    match &cli.command {
        Commands::Client {
            remote,
            local,
            url,
            profile,
            os,
            profile_seq,
            profile_interval,
            fec_mode,
            fec_config,
            doh_provider,
            front_domain,
            ca_file,
            no_utls,
            debug_tls,
            list_fingerprints,
            verify_peer,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
        } => {
            let browser = *profile;
            let os_profile = *os;
            run_client(
                remote,
                local,
                url,
                browser,
                os_profile,
                profile_seq,
                *profile_interval,
                *fec_mode,
                *pool_capacity,
                *pool_block,
                *xdp,
                *xdp_stats,
                config,
                fec_config,
                &doh_provider,
                &front_domain,
                &ca_file,
                *no_utls,
                *debug_tls,
                *list_fingerprints,
                *verify_peer,
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
            pool_capacity,
            pool_block,
            fec_config,
            doh_provider,
            front_domain,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
        } => {
            let browser = *profile;
            let os_profile = *os;
            run_server(
                listen,
                cert,
                key,
                browser,
                os_profile,
                profile_seq,
                *profile_interval,
                *fec_mode,
                *pool_capacity,
                *pool_block,
                *xdp,
                *xdp_stats,
                config,
                fec_config,
                &doh_provider,
                &front_domain,
                *disable_doh,
                *disable_fronting,
                *disable_xor,
                *disable_http3,
            )
            .await?;
        }
    }

    if telemetry::TELEMETRY_ENABLED.load(Ordering::Relaxed) {
        telemetry::flush();
    }
    Ok(())
}

fn parse_profile_entry(entry: &str, default_os: OsProfile) -> Option<FingerprintProfile> {
    let parts: Vec<&str> = entry.split('@').collect();
    let browser_part = parts.get(0)?;
    let browser = match browser_part.parse() {
        Ok(b) => b,
        Err(_) => {
            eprintln!("Invalid browser profile: {}", browser_part);
            return None;
        }
    };
    let os = if let Some(os_part) = parts.get(1) {
        match os_part.parse() {
            Ok(o) => o,
            Err(_) => {
                eprintln!("Invalid OS profile: {}", os_part);
                return None;
            }
        }
    } else {
        default_os
    };
    let mut fp = FingerprintProfile::new(browser, os);
    if fp.client_hello.is_none() {
        eprintln!(
            "No ClientHello found for {}@{}",
            browser_part,
            format!("{:?}", os).to_lowercase()
        );
        return None;
    }
    Some(fp)
}

async fn run_client(
    remote_addr_str: &str,
    local_addr_str: &str,
    url: &str,
    profile: BrowserProfile,
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: FecMode,
    pool_capacity: usize,
    pool_block: usize,
    xdp: bool,
    xdp_stats: bool,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &Vec<String>,
    ca_file: &Option<PathBuf>,
    no_utls: bool,
    debug_tls: bool,
    list_fingerprints: bool,
    verify_peer: bool,
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
) -> std::io::Result<()> {
    let config_path = config.clone();
    if list_fingerprints {
        println!("Available browser fingerprints:");
        for (b, o) in crate::stealth::TlsClientHelloSpoofer::available_profiles() {
            println!(
                "- {}@{}",
                format!("{:?}", b).to_lowercase(),
                format!("{:?}", o).to_lowercase()
            );
        }
        return Ok(());
    }

    let server_addr = remote_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Server address not found")
    })?;

    let local_addr = local_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "Local address invalid",
        )
    })?;

    let socket = std::net::UdpSocket::bind(local_addr)?;
    socket.connect(server_addr)?;
    socket.set_nonblocking(true)?;

    info!("Client connecting to {}", server_addr);

    if xdp_stats {
        tokio::spawn(async move {
            loop {
                println!(
                    "XDP tx: {} bytes, rx: {} bytes",
                    telemetry::XDP_BYTES_SENT.get(),
                    telemetry::XDP_BYTES_RECEIVED.get()
                );
                time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    let (mut fec_cfg, mut stealth_config, mut opt_cfg) = if let Some(cfg) = config_path.as_ref() {
        match AppConfig::from_file(cfg) {
            Ok(c) => {
                if let Err(e) = c.validate() {
                    warn!("Config validation failed: {}", e);
                }
                (c.fec, c.stealth, c.optimize)
            }
            Err(e) => {
                error!("Failed to load config {}: {}", cfg.display(), e);
                (
                    FecConfig::default(),
                    StealthConfig::default(),
                    OptimizeConfig::default(),
                )
            }
        }
    } else {
        let mut fec = if let Some(path) = fec_config {
            match FecConfig::from_file(path) {
                Ok(cfg) => {
                    if let Err(e) = cfg.validate() {
                        warn!("FEC config validation failed: {}", e);
                    }
                    cfg
                }
                Err(e) => {
                    error!("Failed to load FEC config {}: {}", path.display(), e);
                    FecConfig::default()
                }
            }
        } else {
            FecConfig::default()
        };
        (fec, StealthConfig::default(), OptimizeConfig::default())
    };
    fec_cfg.initial_mode = fec_mode;

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
    config.verify_peer(verify_peer);
    if debug_tls {
        config.log_keys();
    }
    if let Some(path) = ca_file {
        if let Err(e) = config.load_verify_locations_from_file(path.to_str().unwrap()) {
            error!("Failed to load CA file {}: {}", path.display(), e);
        }
    }

    let url_parsed =
        url::Url::parse(url).unwrap_or_else(|_| url::Url::parse("https://example.com/").unwrap());
    let mut stealth_config = stealth_config;
    stealth_config.browser_profile = profile;
    stealth_config.os_profile = os;
    stealth_config.enable_doh = !disable_doh;
    stealth_config.doh_provider = doh_provider.to_string();
    stealth_config.enable_domain_fronting = !disable_fronting;
    stealth_config.fronting_domains = front_domain.clone();
    stealth_config.enable_xor_obfuscation = !disable_xor;
    stealth_config.enable_http3_masquerading = !disable_http3;
    telemetry!(telemetry::STEALTH_BROWSER_PROFILE.set(stealth_config.browser_profile as i64));
    telemetry!(telemetry::STEALTH_OS_PROFILE.set(stealth_config.os_profile as i64));

    let host = url_parsed.host_str().unwrap_or("example.com");
    let opt_params = if config_path.is_some() {
        OptimizeConfig {
            pool_capacity: opt_cfg.pool_capacity,
            block_size: opt_cfg.block_size,
            enable_xdp: opt_cfg.enable_xdp || xdp,
        }
    } else {
        OptimizeConfig {
            pool_capacity,
            block_size: pool_block,
            enable_xdp: xdp,
        }
    };
    let mut conn = QuicFuscateConnection::new_client(
        host,
        local_addr,
        server_addr,
        config,
        stealth_config.clone(),
        fec_cfg,
        opt_params,
        !no_utls,
    )
    .expect("failed to create client connection");

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq
            .iter()
            .filter_map(|s| parse_profile_entry(s, os))
            .collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

    if profile_interval > 0 && profiles.len() > 1 {
        let sm = conn.stealth_manager();
        sm.start_profile_rotation(profiles, std::time::Duration::from_secs(profile_interval));
    }

    let mut buf = [0; 65535];
    let mut out = [0; 65535];

    // Send initial packet
    if let Ok(len) = conn.send(&mut out) {
        if len > 0 {
            telemetry!(telemetry::BYTES_SENT.inc_by(len as u64));
            #[cfg(unix)]
            {
                let zc = ZeroCopyBuffer::new(&[&out[..len]]);
                zc.send(socket.as_raw_fd());
            }
            #[cfg(not(unix))]
            {
                socket.send(&out[..len])?;
            }
            info!("Sent initial packet of size {}", len);
        }
    }

    let mut request_sent = false;
    let mut shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutdown signal received");
                let _ = conn.conn.close(true, 0x0, b"ctrl_c");
                break;
            }
            _ = async {
                // Process incoming packets
                match {
                    #[cfg(unix)]
                    {
                        let mut slice = [&mut buf[..]];
                        let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
                        let r = zc.recv(socket.as_raw_fd());
                        if r >= 0 { Ok(r as usize) } else { Err(std::io::Error::last_os_error()) }
                    }
                    #[cfg(not(unix))]
                    {
                        socket.recv(&mut buf)
                    }
                } {
                    Ok(len) => {
                        telemetry!(telemetry::BYTES_RECEIVED.inc_by(len as u64));
                        let _ = conn.recv(&buf[..len]);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        error!("Failed to read from socket: {}", e);
                        return;
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
                    telemetry!(telemetry::BYTES_SENT.inc_by(len as u64));
                    #[cfg(unix)]
                    {
                        let zc = ZeroCopyBuffer::new(&[&out[..len]]);
                        zc.send(socket.as_raw_fd());
                    }
                    #[cfg(not(unix))]
                    {
                        socket.send(&out[..len])?;
                    }
                }
                Ok(_) => break,
                Err(crate::error::ConnectionError::Quiche(quiche::Error::Done)) => break,
                Err(e) => {
                    error!("Send failed: {:?}", e);
                    break;
                }
            }
        }

                conn.update_state();
                info!(
                    "client stats: RTT {:.0} ms, Loss {:.2}%",
                    conn.stats.rtt,
                    conn.stats.loss_rate * 100.0
                );
                conn.conn.on_timeout();

                // Sleep to avoid busy-looping
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            } => {}
        }
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
    pool_capacity: usize,
    pool_block: usize,
    xdp: bool,
    xdp_stats: bool,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &Vec<String>,
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
) -> std::io::Result<()> {
    let config_path = config.clone();
    let socket = std::net::UdpSocket::bind(listen_addr)?;
    socket.set_nonblocking(true)?;
    info!("Server listening on {}", listen_addr);

    if xdp_stats {
        tokio::spawn(async move {
            loop {
                println!(
                    "XDP tx: {} bytes, rx: {} bytes",
                    telemetry::XDP_BYTES_SENT.get(),
                    telemetry::XDP_BYTES_RECEIVED.get()
                );
                time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    let (mut fec_cfg, mut stealth_cfg, mut opt_cfg) = if let Some(cfg) = config_path.as_ref() {
        match AppConfig::from_file(cfg) {
            Ok(c) => {
                if let Err(e) = c.validate() {
                    warn!("Config validation failed: {}", e);
                }
                (c.fec, c.stealth, c.optimize)
            }
            Err(e) => {
                error!("Failed to load config {}: {}", cfg.display(), e);
                (
                    FecConfig::default(),
                    StealthConfig::default(),
                    OptimizeConfig::default(),
                )
            }
        }
    } else {
        let mut fec = if let Some(path) = fec_config {
            match FecConfig::from_file(path) {
                Ok(cfg) => {
                    if let Err(e) = cfg.validate() {
                        warn!("FEC config validation failed: {}", e);
                    }
                    cfg
                }
                Err(e) => {
                    error!("Failed to load FEC config {}: {}", path.display(), e);
                    FecConfig::default()
                }
            }
        } else {
            FecConfig::default()
        };
        (fec, StealthConfig::default(), OptimizeConfig::default())
    };
    fec_cfg.initial_mode = fec_mode;

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
    let initial_sc = stealth_cfg.clone();
    let stealth_config = Arc::new(Mutex::new(initial_sc));
    {
        let mut sc = stealth_config.lock().unwrap();
        sc.browser_profile = profile;
        sc.os_profile = os;
        sc.enable_doh = !disable_doh;
        sc.doh_provider = doh_provider.to_string();
        sc.enable_domain_fronting = !disable_fronting;
        sc.fronting_domains = front_domain.clone();
        sc.enable_xor_obfuscation = !disable_xor;
        sc.enable_http3_masquerading = !disable_http3;
        telemetry!(telemetry::STEALTH_BROWSER_PROFILE.set(sc.browser_profile as i64));
        telemetry!(telemetry::STEALTH_OS_PROFILE.set(sc.os_profile as i64));
    }
    let opt_params = if config_path.is_some() {
        OptimizeConfig {
            pool_capacity: opt_cfg.pool_capacity,
            block_size: opt_cfg.block_size,
            enable_xdp: opt_cfg.enable_xdp || xdp,
        }
    } else {
        OptimizeConfig {
            pool_capacity,
            block_size: pool_block,
            enable_xdp: xdp,
        }
    };

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq
            .iter()
            .filter_map(|s| parse_profile_entry(s, os))
            .collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

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

    let mut shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutdown signal received");
                for conn in clients.values_mut() {
                    let _ = conn.conn.close(true, 0x0, b"ctrl_c");
                }
                break;
            }
            _ = async {
                match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                telemetry!(telemetry::BYTES_RECEIVED.inc_by(len as u64));
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
                        fec_cfg.clone(),
                        opt_params,
                    )
                    .expect("failed to create server connection")
                });

                if let Err(e) = client_conn.recv(&buf[..len]) {
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
                        telemetry!(telemetry::BYTES_SENT.inc_by(len as u64));
                        if let Err(e) = socket.send_to(&out[..len], addr) {
                            error!("Failed to send packet to {}: {}", addr, e);
                        }
                    }
                    Ok(_) => break,
                    Err(crate::error::ConnectionError::Quiche(quiche::Error::Done)) => break,
                    Err(e) => {
                        error!("Send failed to {}: {:?}", addr, e);
                        break;
                    }
                }
            }
            conn.update_state();
            info!(
                "client {} stats: RTT {:.0} ms, Loss {:.2}%",
                addr,
                conn.stats.rtt,
                conn.stats.loss_rate * 100.0
            );
            conn.conn.on_timeout();
        }

                // Clean up closed connections
                clients.retain(|_, conn| !conn.conn.is_closed());

                // Sleep to avoid busy-looping
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            } => {}
        }
    }

    Ok(())
}
