//! QuicFuscate Server Implementation
//!
//! This module provides the canonical server runtime and retained server-side
//! support surfaces for this fork.
//! - Standalone UDP accept loop and shared server runtime ownership
//! - Session management, IP pool allocation, and limit enforcement
//! - Admin/control-plane wiring and metrics surfaces
//! - Optional host routing integration where platform support exists
//!
//! # Architecture
//!
//! ```text
//! Canonical server runtime flow:
//! - Track sessions and assign IPs
//! - Route traffic via TUN and optionally host routing helpers
//! - Provide the shared ownership model used by the standalone live UDP server path
//! ```

mod accept;
pub mod admin;
pub mod admin_http;
pub mod admin_logs;
pub mod auth_frame;
pub mod bandwidth;
mod bootstrap;
mod config;
mod ddos;
mod dns_signals;
#[doc(hidden)]
pub mod fsutil;
mod http;
pub mod icmp;
mod ip_pool;
pub mod isolation;
mod limits;
mod live_auth;
mod live_state;
pub mod metrics;
mod qkey_issue;
pub mod qkey_registry;
mod qkey_registry_storage;
pub mod replay_window;
pub mod revocation;
mod routing;
mod runtime_admin;
mod runtime_impl;
mod session;
pub mod systemd;
#[cfg(test)]
mod tests_inline;
mod tun_path;

pub use accept::{
    AcceptConfig, AcceptDecision, AcceptLoop, AcceptStats, AcceptStatsSnapshot,
    IpConnectionTracker, RejectReason, DEFAULT_MAX_CONNECTIONS_PER_IP,
};
#[cfg(unix)]
pub use admin::AdminServer;
#[cfg(any(test, feature = "rust-tests"))]
pub use admin::DefaultAdminHandler;
pub use admin::{
    encode_admin_command, normalize_admin_client_id, normalize_admin_command, normalize_admin_ip,
    snapshots_to_client_info, AdminCommand, AdminHandler, AdminResponse, ClientIdentity,
    ClientInfo, ClientSnapshot, MAX_ADMIN_COMMAND_BYTES, MAX_ADMIN_COMMAND_VALUE_BYTES,
};
pub use admin_http::{
    validate_admin_web_max_connections, validate_admin_web_operation_timeout_ms,
    AdminHttpAdmissionSnapshot, AdminHttpHandler, AdminHttpOperationDiagnostics,
    AdminHttpOperationSnapshot, AdminHttpServer, DEFAULT_ADMIN_WEB_MAX_CONNECTIONS,
    DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS, MAX_ADMIN_WEB_CONNECTIONS,
    MAX_ADMIN_WEB_OPERATION_TIMEOUT_MS, MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS,
};
pub use bandwidth::{
    BandwidthDecision, BandwidthDirection, BandwidthLimiter, BandwidthPolicy, BandwidthStats,
    PerClientBandwidthManager, QuotaPeriod, QuotaTracker,
};
pub use bootstrap::*;
pub use config::*;
use dns_signals::*;
pub use ip_pool::{IpPool, Ipv6Pool};
pub use isolation::{
    AssignedClientIps, ClientIsolationManager, DownlinkRoute, IsolationStats, UplinkDrop,
    UplinkRoute,
};
#[cfg(feature = "rate_limiter")]
pub use limits::load_rate_limit_config_from_env;
pub use limits::{
    AuthPolicyConfig, ConnectionLimiter, GlobalRateLimiter, RateLimitConfig, RateLimiter,
};
#[cfg(feature = "rate_limiter")]
pub use limits::{
    BlacklistSync, GeoIpBlocker, GeoIpConfig, GeoIpError, GeoIpLookupError, GeoIpStatus,
};
pub use live_auth::*;
pub use live_state::*;
#[cfg(any(test, feature = "rust-tests"))]
pub use metrics::GlobalMetricsServer;
pub use metrics::{Metrics, RoutingOutcome, TunDownlinkBackpressureDrop};
pub use qkey_issue::*;
pub use routing::{detect_wan_interface, RoutingError, RoutingManager};
pub use runtime_admin::*;
pub use runtime_impl::*;
pub use session::{Session, SessionError, SessionId, SessionManager, SessionStats};
pub use tun_path::*;

use self::admin_http::{AdminAuth, IssueQKeyRequest};
use self::qkey_registry::{QKeyEntry, QKeyRecord, QKeyRegistry};
use parking_lot::{Mutex, RwLock};
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::core::QuicFuscateConnection;
use crate::fec::FecConfig;
use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;
use crate::optimize::OptimizeConfig;
#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
#[cfg(unix)]
use crate::optimize::ZeroCopyRecvBuffer;
use crate::stealth::{
    BrowserProfile, FingerprintProfile, OsFingerprintProfile, OsProfile, StealthConfig,
    StealthMode, StealthRuntimeOwner,
};
use qf_engine_types::{DataPlaneFault, EngineConfig, EngineError, RuntimePolicyGeneration};

const SERVER_STATS_LOG_INTERVAL: Duration = Duration::from_secs(1);
const LIVE_UDP_DATAGRAM_BUFFER_SIZE: usize = 65_535;
const _: () = assert!(LIVE_UDP_DATAGRAM_BUFFER_SIZE >= 1500);
const MAX_PENDING_TUN_DOWNLINKS: usize = 256;
const MAX_PENDING_TUN_DOWNLINK_BYTES: usize = 384 * 1024;
const MAX_PENDING_TUN_DOWNLINKS_PER_TARGET: usize = 32;
const MAX_PENDING_TUN_DOWNLINK_AGE: Duration = Duration::from_secs(5);
const MAX_MASQUE_DOWNLINK_RESPONSES: usize = 128;
const MAX_MASQUE_DOWNLINK_RESPONSE_BYTES: usize = 192 * 1024;
