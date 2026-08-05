//! Client-owned local DNS proxy and system resolver lifecycle.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::platform::{self, DnsConfig, PlatformBackend};
use super::runtime::SharedRuntime;
use crate::dns::{
    process_dns_query_with_admission, DnsAdmission, DnsAdmissionIdentity, DnsAdmissionSnapshot,
    DnsProxyConfig, DnsProxyError,
};
use crate::engine::{EngineConfig, EngineError};

const DNS_PACKET_LIMIT: usize = 4096;
const DNS_LISTEN_PORT: u16 = 53;
const LOCAL_DNS_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Owns the local DNS proxy, the system resolver mutation, and their cleanup.
pub struct ClientDnsRuntime {
    shutdown: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
    admission: Arc<DnsAdmission>,
    platform: Box<dyn PlatformBackend>,
    dns_configured: bool,
}

impl ClientDnsRuntime {
    /// Resolve and pin the configured DoH endpoint before firewall or resolver changes.
    pub fn prepare(config: &EngineConfig) -> Result<DnsProxyConfig, EngineError> {
        Self::prepare_endpoint(&config.stealth.doh_provider)
    }

    /// Resolve and pin one DoH endpoint before firewall or resolver changes.
    pub fn prepare_endpoint(endpoint: &str) -> Result<DnsProxyConfig, EngineError> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            return Err(EngineError::Config(
                "DoH is enabled but stealth.doh_provider is empty".to_string(),
            ));
        }
        DnsProxyConfig::for_client_endpoints(vec![endpoint.to_string()]).map_err(|error| {
            EngineError::Config(format!("client DNS proxy configuration: {error}"))
        })
    }

    /// Start the client DNS proxy and redirect the active system resolver to it.
    ///
    /// DoH endpoint addresses are resolved before the system resolver changes.
    /// This is required to prevent the proxy from recursively resolving its own
    /// HTTPS endpoint through the listener it is currently serving.
    pub fn start(
        runtime: &SharedRuntime,
        config: &EngineConfig,
        tun_name: &str,
    ) -> Result<Self, EngineError> {
        let proxy_config = Self::prepare(config)?;
        Self::start_with_config(runtime.handle(), proxy_config, tun_name)
    }

    /// Start the client DNS proxy on an already-running Tokio runtime.
    pub fn start_with_endpoint(
        runtime: &Handle,
        endpoint: &str,
        tun_name: &str,
    ) -> Result<Self, EngineError> {
        let proxy_config = Self::prepare_endpoint(endpoint)?;
        Self::start_with_config(runtime, proxy_config, tun_name)
    }

    /// Commit a prepared DoH configuration to the local resolver and proxy.
    pub fn start_with_config(
        runtime: &Handle,
        proxy_config: DnsProxyConfig,
        tun_name: &str,
    ) -> Result<Self, EngineError> {
        if proxy_config.listen_port != DNS_LISTEN_PORT {
            return Err(EngineError::Config(format!(
                "client DNS proxy must listen on UDP port {DNS_LISTEN_PORT}, got {}",
                proxy_config.listen_port
            )));
        }
        if !proxy_config.use_doh || proxy_config.doh_endpoints.is_empty() {
            return Err(EngineError::Config(
                "client DNS proxy requires at least one DoH endpoint".to_string(),
            ));
        }
        if !proxy_config.upstream_resolvers.is_empty() {
            return Err(EngineError::Config(
                "client DNS proxy does not accept plain DNS upstream resolvers".to_string(),
            ));
        }
        let admission =
            Arc::new(DnsAdmission::try_new(proxy_config.admission).map_err(|error| {
                EngineError::Config(format!("client DNS admission configuration: {error}"))
            })?);
        let tun_name = tun_name.trim();
        if tun_name.is_empty() {
            return Err(EngineError::Tun(
                "client DNS proxy requires an active TUN interface name".to_string(),
            ));
        }
        proxy_config.prepare_doh_client().map_err(|error| {
            EngineError::Config(format!("client DNS proxy endpoint preparation failed: {error}"))
        })?;

        let listen_port = proxy_config.listen_port;
        let ipv4_socket =
            bind_local_socket(runtime, SocketAddr::from(([127, 0, 0, 1], listen_port)))?;
        let ipv6_socket =
            bind_local_socket(runtime, SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], listen_port)))
                .map_err(|error| {
                    log::warn!(
                        "Client DoH IPv6 listener unavailable; continuing with IPv4 only: {error}"
                    );
                    error
                })
                .ok();

        let platform_backend: Box<dyn PlatformBackend> = Box::new(platform::native());
        platform_backend.set_dns_interface_name(tun_name);
        let dns_config = DnsConfig { servers: vec![LOCAL_DNS_ADDRESS], search_domains: Vec::new() };
        if let Err(error) = platform_backend.set_dns(&dns_config) {
            let restore = platform_backend.restore_dns().err();
            platform_backend.clear_dns_interface_name();
            let detail = restore.map_or_else(
                || error.to_string(),
                |restore_error| format!("{error}; DNS rollback failed: {restore_error}"),
            );
            return Err(EngineError::Internal(format!(
                "client DNS system resolver activation failed: {detail}"
            )));
        }

        let shutdown = Arc::new(Notify::new());
        let mut tasks = vec![spawn_listener(
            runtime,
            ipv4_socket,
            proxy_config.clone(),
            Arc::clone(&shutdown),
            Arc::clone(&admission),
        )];
        if let Some(socket) = ipv6_socket {
            tasks.push(spawn_listener(
                runtime,
                socket,
                proxy_config,
                Arc::clone(&shutdown),
                Arc::clone(&admission),
            ));
            log::info!(
                "Client DoH DNS proxy active on 127.0.0.1:{} and [::1]:{}",
                listen_port,
                listen_port
            );
        } else {
            log::info!("Client DoH DNS proxy active on 127.0.0.1:{}", listen_port);
        }
        Ok(Self { shutdown, tasks, admission, platform: platform_backend, dns_configured: true })
    }

    /// Restore the prior system resolver and stop the proxy tasks.
    pub fn stop(&mut self, runtime: &SharedRuntime) -> Result<(), EngineError> {
        runtime.block_on(self.stop_async())
    }

    /// Restore the prior system resolver and stop the proxy tasks from async code.
    pub async fn stop_async(&mut self) -> Result<(), EngineError> {
        if self.dns_configured {
            self.platform.restore_dns().map_err(|error| {
                EngineError::Internal(format!("client DNS system resolver restore failed: {error}"))
            })?;
            self.platform.clear_dns_interface_name();
            self.dns_configured = false;
        }

        self.shutdown.notify_waiters();
        let handles = std::mem::take(&mut self.tasks);
        let mut failure = None;
        for handle in handles {
            handle.abort();
            if let Err(error) = handle.await {
                if !error.is_cancelled() && failure.is_none() {
                    failure = Some(error.to_string());
                }
            }
        }
        if let Some(error) = failure {
            return Err(EngineError::Internal(format!(
                "client DNS proxy task shutdown failed: {error}"
            )));
        }
        log::info!("Client DoH DNS proxy stopped and system DNS restored");
        Ok(())
    }

    /// Return listener admission counters for health and local proof.
    pub fn admission_snapshot(&self) -> DnsAdmissionSnapshot {
        self.admission.snapshot()
    }
}

impl Drop for ClientDnsRuntime {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        for task in &self.tasks {
            task.abort();
        }
        if self.dns_configured {
            match self.platform.restore_dns() {
                Ok(()) => {
                    self.platform.clear_dns_interface_name();
                    self.dns_configured = false;
                }
                Err(error) => {
                    log::error!("Client DNS resolver restore during drop failed: {error}");
                }
            }
        }
    }
}

fn bind_local_socket(runtime: &Handle, address: SocketAddr) -> Result<UdpSocket, EngineError> {
    let socket = std::net::UdpSocket::bind(address)
        .map_err(|error| EngineError::Io(format!("DNS proxy bind {address}: {error}")))?;
    socket.set_nonblocking(true).map_err(|error| {
        EngineError::Io(format!("DNS proxy nonblocking setup {address}: {error}"))
    })?;
    let _runtime_guard = runtime.enter();
    UdpSocket::from_std(socket)
        .map_err(|error| EngineError::Io(format!("DNS proxy Tokio setup {address}: {error}")))
}

fn spawn_listener(
    runtime: &Handle,
    socket: UdpSocket,
    config: DnsProxyConfig,
    shutdown: Arc<Notify>,
    admission: Arc<DnsAdmission>,
) -> JoinHandle<()> {
    runtime.spawn(async move {
        serve_listener(socket, config, shutdown, admission).await;
    })
}

async fn serve_listener(
    socket: UdpSocket,
    config: DnsProxyConfig,
    shutdown: Arc<Notify>,
    admission: Arc<DnsAdmission>,
) {
    let mut buffer = [0u8; DNS_PACKET_LIMIT];
    loop {
        let received = tokio::select! {
            _ = shutdown.notified() => break,
            result = socket.recv_from(&mut buffer) => result,
        };
        let (length, peer) = match received {
            Ok(value) => value,
            Err(error) => {
                log::warn!("Client DNS proxy receive failed: {error}");
                continue;
            }
        };
        if length == 0 {
            continue;
        }

        let identity = DnsAdmissionIdentity::Source(peer.ip());
        let response = match process_dns_query_with_admission(
            &buffer[..length],
            &config,
            &admission,
            identity,
        )
        .await
        {
            Ok(response) => response,
            Err(DnsProxyError::AdmissionRejected(reason)) => {
                log::debug!(
                    "Client DNS query dropped before upstream resolution from {peer}: {reason}"
                );
                continue;
            }
            Err(error) => {
                log::debug!("Client DNS query rejected: {error}");
                continue;
            }
        };
        if response.len() > DNS_PACKET_LIMIT {
            log::warn!(
                "Client DNS response exceeded the UDP proxy limit: {} bytes",
                response.len()
            );
            continue;
        }
        if let Err(error) = socket.send_to(&response, peer).await {
            log::warn!("Client DNS proxy response failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("Tokio runtime")
    }

    #[test]
    fn start_rejects_non_standard_dns_port_before_platform_mutation() {
        let runtime = test_runtime();
        let mut config =
            DnsProxyConfig::for_client_endpoints(vec!["https://127.0.0.1/dns-query".to_string()])
                .expect("client config");
        config.listen_port = 5353;

        let result = ClientDnsRuntime::start_with_config(&runtime.handle(), config, "tun0");

        assert!(matches!(result, Err(EngineError::Config(_))));
    }

    #[test]
    fn start_rejects_server_dns_configuration_before_platform_mutation() {
        let runtime = test_runtime();

        let result = ClientDnsRuntime::start_with_config(
            &runtime.handle(),
            DnsProxyConfig::default(),
            "tun0",
        );

        assert!(matches!(result, Err(EngineError::Config(_))));
    }

    #[test]
    fn listener_drops_excess_queries_and_exports_admission_counters() {
        let runtime = test_runtime();
        runtime.block_on(async {
            let listener = UdpSocket::bind("127.0.0.1:0").await.expect("listener bind");
            let listener_addr = listener.local_addr().expect("listener address");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
            let shutdown = Arc::new(Notify::new());
            let admission = Arc::new(
                DnsAdmission::try_new(crate::dns::DnsAdmissionConfig {
                    max_in_flight: 1,
                    global_pps: 1,
                    global_burst: 1,
                    per_identity_pps: 100,
                    per_identity_burst: 100,
                    max_identities: 2,
                    idle_timeout: std::time::Duration::from_secs(60),
                })
                .expect("admission config"),
            );
            let mut config = DnsProxyConfig::default();
            config.doh_endpoints.clear();
            config.upstream_resolvers.clear();
            config.use_doh = false;
            let task = tokio::spawn(serve_listener(
                listener,
                config,
                Arc::clone(&shutdown),
                Arc::clone(&admission),
            ));
            let query = vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
                0x01,
            ];
            client.send_to(&query, listener_addr).await.expect("first query");
            client.send_to(&query, listener_addr).await.expect("second query");

            let mut response = [0u8; DNS_PACKET_LIMIT];
            let (length, _) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.recv_from(&mut response),
            )
            .await
            .expect("first query response timeout")
            .expect("first query response");
            assert_eq!(response[0..2], query[0..2]);
            assert!(length >= 12);
            let second = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                client.recv_from(&mut response),
            )
            .await;
            assert!(second.is_err(), "excess query must be dropped without amplification");

            let snapshot = admission.snapshot();
            assert_eq!(snapshot.accepted, 1);
            assert_eq!(snapshot.rejected_global_rate, 1);
            assert_eq!(snapshot.tracked_identities, 1);

            shutdown.notify_waiters();
            task.abort();
            let _ = task.await;
        });
    }
}
