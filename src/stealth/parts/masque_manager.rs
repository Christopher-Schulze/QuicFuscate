// --- 5. XOR-based Traffic Obfuscation

// --- 6. Advanced TLS Features: Cert-Chain, Session Tickets, etc.

// --- 7. MASQUE/CONNECT-UDP Implementation

/// MASQUE (Multiplexed Application Substrate over QUIC Encryption) support.
/// Provides best-effort CONNECT-UDP control/data request management.
pub struct MasqueManager {
    /// Active MASQUE tunnels.
    #[cfg(any(test, feature = "rust-tests"))]
    tunnels: Arc<Mutex<HashMap<String, MasqueTunnel>>>,
    /// HTTP/3 client for CONNECT-UDP.
    #[cfg(any(test, feature = "rust-tests"))]
    _h3_client: Arc<Client>,
}

#[cfg(any(test, feature = "rust-tests"))]
impl Default for MasqueManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "rust-tests"))]
#[derive(Clone)]
struct MasqueTunnel {
    /// Tunnel ID.
    id: String,
    /// Target endpoint.
    target: String,
    /// Proxy endpoint.
    proxy: String,
    /// Creation time.
    created: std::time::Instant,
    /// Bytes sent.
    bytes_sent: Arc<AtomicUsize>,
    /// Bytes received.
    bytes_recv: Arc<AtomicUsize>,
}

impl MasqueManager {
    /// Create a new MASQUE manager with optimized HTTP/3 client.
    fn new_internal() -> Self {
        #[cfg(any(test, feature = "rust-tests"))]
        {
            // Use an optimized HTTP/3 client with connection pooling.
            let h3_client = Client::builder()
                .pool_max_idle_per_host(8)
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .http2_keep_alive_interval(std::time::Duration::from_secs(30))
                .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new());

            Self { tunnels: Arc::new(Mutex::new(HashMap::new())), _h3_client: Arc::new(h3_client) }
        }

        #[cfg(not(any(test, feature = "rust-tests")))]
        {
            Self {}
        }
    }

    /// Creates a new MASQUE manager with an HTTP/3 client (test-only public constructor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn new() -> Self {
        Self::new_internal()
    }

    /// Process incoming MASQUE capsule data
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn process_incoming_capsule(
        &self,
        tunnel_id: &str,
        capsule_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if capsule_data.len() < 2 {
            return Err("Capsule too short".into());
        }

        let mut offset = 0;
        let capsule_type = capsule_data[offset];
        offset += 1;

        if offset >= capsule_data.len() {
            return Err("Missing capsule length".into());
        }

        // Parse varint length
        let (len, bytes_read) = if capsule_data[offset] < 64 {
            (capsule_data[offset] as usize, 1)
        } else if offset + 1 < capsule_data.len() && capsule_data[offset] & 0xC0 == 0x40 {
            let len = (((capsule_data[offset] & 0x3F) as usize) << 8)
                | (capsule_data[offset + 1] as usize);
            (len, 2)
        } else {
            return Err("Invalid varint".into());
        };
        offset += bytes_read;
        if offset + len > capsule_data.len() {
            return Err("Capsule payload length out of bounds".into());
        }

        if capsule_type == 0x00 {
            // DATAGRAM capsule
            let data = capsule_data[offset..offset + len].to_vec();

            // Update stats
            if let Ok(tunnels) = self.tunnels.lock() {
                if let Some(tunnel) = tunnels.get(tunnel_id) {
                    tunnel.bytes_recv.fetch_add(data.len(), Ordering::Relaxed);
                }
            }

            Ok(data)
        } else {
            Err(format!("Unknown capsule type: {}", capsule_type).into())
        }
    }

    /// Establish a CONNECT-UDP tunnel with async HTTP/3 negotiation.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn establish_tunnel(
        &self,
        proxy: &str,
        target: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Generate tunnel ID
        let tunnel_id = format!("masque_{:x}", rand::random::<u64>());

        // Create HTTP/3 CONNECT-UDP request headers
        let connect_headers = self.build_connect_headers(proxy, target)?;

        // Async tunnel establishment via Tokio runtime
        let h3_client = Arc::clone(&self._h3_client);
        let proxy_url = format!("https://{}", proxy);
        let target_str = target.to_string();
        let tunnel_id_clone = tunnel_id.clone();

        // Spawn async task for HTTP/3 CONNECT-UDP
        let Some(rt) = DOH_RUNTIME.as_ref() else {
            return Err("DoH runtime unavailable - cannot establish MASQUE tunnel".into());
        };
        rt.spawn(async move {
            match Self::async_establish_tunnel(&h3_client, &proxy_url, &target_str, connect_headers)
                .await
            {
                Ok(_) => info!("MASQUE tunnel {} established successfully", tunnel_id_clone),
                Err(e) => error!("Failed to establish MASQUE tunnel {}: {}", tunnel_id_clone, e),
            }
        });

        // Store tunnel metadata
        let tunnel = MasqueTunnel {
            id: tunnel_id.clone(),
            target: target.to_string(),
            proxy: proxy.to_string(),
            created: std::time::Instant::now(),
            bytes_sent: Arc::new(AtomicUsize::new(0)),
            bytes_recv: Arc::new(AtomicUsize::new(0)),
        };

        if let Ok(mut tunnels) = self.tunnels.lock() {
            // Cleanup old tunnels (>5 min).
            tunnels.retain(|_, t| t.created.elapsed().as_secs() < 300);
            tunnels.insert(tunnel_id.clone(), tunnel);
        }

        info!("MASQUE tunnel scheduled: {} -> {} via {}", tunnel_id, target, proxy);
        Ok(tunnel_id)
    }

    /// Async helper for HTTP/3 CONNECT-UDP negotiation
    #[cfg(any(test, feature = "rust-tests"))]
    async fn async_establish_tunnel(
        client: &Client,
        proxy_url: &str,
        target: &str,
        headers: Vec<crate::transport::h3::Header>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Build URL from pseudo-path (CONNECT target form is not directly representable in reqwest).
        let path = headers
            .iter()
            .find(|h| h.name() == b":path")
            .and_then(|h| std::str::from_utf8(h.value()).ok())
            .unwrap_or("/");
        let url = format!("{}{}", proxy_url.trim_end_matches('/'), path);
        let resp = client
            .request(reqwest::Method::CONNECT, &url)
            .header("capsule-protocol", "?1")
            .header("x-connect-udp-target", target)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(format!("CONNECT-UDP setup failed with status {}", resp.status()).into());
        }
        Ok(())
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn build_connect_headers(
        &self,
        proxy: &str,
        target: &str,
    ) -> Result<Vec<crate::transport::h3::Header>, Box<dyn std::error::Error>> {
        use crate::transport::h3::Header;
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| format!("Invalid MASQUE target '{}', expected host:port", target))?;
        if host.is_empty() || port.is_empty() {
            return Err(format!("Invalid MASQUE target '{}', expected host:port", target).into());
        }

        Ok(vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-udp"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", proxy.as_bytes()),
            Header::new(b":path", format!("/.well-known/masque/udp/{}/{}/", host, port).as_bytes()),
            Header::new(b"capsule-protocol", b"?1"),
        ])
    }

    /// Send data through MASQUE tunnel with async batching.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_through_tunnel(
        &self,
        tunnel_id: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, target, sent_counter, tunnel_ident) = if let Ok(tunnels) = self.tunnels.lock() {
            if let Some(tunnel) = tunnels.get(tunnel_id) {
                (
                    tunnel.proxy.clone(),
                    tunnel.target.clone(),
                    Arc::clone(&tunnel.bytes_sent),
                    tunnel.id.clone(),
                )
            } else {
                return Err(format!("Tunnel {} not found", tunnel_id).into());
            }
        } else {
            return Err("Failed to lock MASQUE tunnel table".into());
        };

        // Build optimized HTTP/3 DATA capsule
        let capsule = self.build_data_capsule(data);
        let client = Arc::clone(&self._h3_client);
        let Some(rt) = DOH_RUNTIME.as_ref() else {
            return Err("DoH runtime unavailable - cannot send through MASQUE tunnel".into());
        };
        rt.spawn(async move {
            let (host, port) = match target.rsplit_once(':') {
                Some(v) => v,
                None => {
                    error!("MASQUE tunnel {} has invalid target '{}'", tunnel_ident, target);
                    return;
                }
            };
            let url = format!("https://{}/.well-known/masque/udp/{}/{}/", proxy, host, port);
            if let Err(e) = client
                .post(url)
                .header("capsule-protocol", "?1")
                .header("content-type", "application/masque-capsule")
                .body(capsule)
                .send()
                .await
            {
                error!("MASQUE async data send failed for tunnel {}: {}", tunnel_ident, e);
            }
        });

        // Update stats atomically
        sent_counter.fetch_add(data.len(), Ordering::Release);

        // Telemetry
        crate::telemetry::MASQUE_BYTES_SENT.inc_by(data.len() as u64);

        Ok(())
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn build_data_capsule(&self, data: &[u8]) -> Vec<u8> {
        let mut capsule = Vec::with_capacity(data.len() + 16);

        // Capsule type (DATAGRAM = 0x00)
        capsule.push(0x00);

        // Capsule length (varint)
        let len = data.len() as u64;
        if len < 64 {
            capsule.push(len as u8);
        } else {
            capsule.push(0x40 | ((len >> 8) as u8));
            capsule.push((len & 0xFF) as u8);
        }

        // Capsule data
        capsule.extend_from_slice(data);

        capsule
    }

    /// Get tunnel statistics.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn get_tunnel_stats(&self, tunnel_id: &str) -> Option<(usize, usize, u64)> {
        if let Ok(tunnels) = self.tunnels.lock() {
            if let Some(tunnel) = tunnels.get(tunnel_id) {
                return Some((
                    tunnel.bytes_sent.load(Ordering::Relaxed),
                    tunnel.bytes_recv.load(Ordering::Relaxed),
                    tunnel.created.elapsed().as_secs(),
                ));
            }
        }
        None
    }
}
