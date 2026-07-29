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
#[doc(hidden)]
pub mod fsutil;
pub mod icmp;
mod ip_pool;
pub mod isolation;
mod limits;
pub mod metrics;
pub mod qkey_registry;
mod qkey_registry_storage;
pub mod replay_window;
pub mod revocation;
mod routing;
mod session;
pub mod systemd;

pub use accept::{
    AcceptConfig, AcceptDecision, AcceptLoop, AcceptStats, AcceptStatsSnapshot,
    IpConnectionTracker, RejectReason, DEFAULT_MAX_CONNECTIONS_PER_IP,
};
#[cfg(unix)]
pub use admin::AdminServer;
#[cfg(any(test, feature = "rust-tests"))]
pub use admin::DefaultAdminHandler;
pub use admin::{
    snapshots_to_client_info, AdminCommand, AdminHandler, AdminResponse, ClientIdentity,
    ClientInfo, ClientSnapshot,
};
pub use admin_http::{AdminHttpHandler, AdminHttpServer};
pub use bandwidth::{BandwidthLimiter, BandwidthStats, PerClientBandwidthManager, QuotaTracker};
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
pub use limits::{BlacklistSync, GeoIpBlocker, GeoIpConfig};
#[cfg(any(test, feature = "rust-tests"))]
pub use metrics::GlobalMetricsServer;
pub use metrics::{Metrics, RoutingOutcome, TunDownlinkBackpressureDrop};
pub use routing::{detect_wan_interface, RoutingError, RoutingManager};
pub use session::{Session, SessionError, SessionId, SessionManager, SessionStats};

use self::admin_http::{AdminAuth, IssueQKeyRequest};
use self::qkey_registry::{QKeyEntry, QKeyRecord, QKeyRegistry};
use parking_lot::RwLock;
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
use crate::engine::{EngineConfig, EngineError};
use crate::fec::FecConfig;
use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;
use crate::optimize::OptimizeConfig;
#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
use crate::stealth::{
    BrowserProfile, FingerprintProfile, OsFingerprintProfile, OsProfile, PacketNormalizer,
    StealthConfig, StealthMode,
};

const SERVER_STATS_LOG_INTERVAL: Duration = Duration::from_secs(1);
const LIVE_UDP_DATAGRAM_BUFFER_SIZE: usize = 65_535;
const _: () = assert!(LIVE_UDP_DATAGRAM_BUFFER_SIZE >= 1500);
const MAX_PENDING_TUN_DOWNLINKS: usize = 256;
const MAX_PENDING_TUN_DOWNLINK_BYTES: usize = 384 * 1024;
const MAX_PENDING_TUN_DOWNLINKS_PER_TARGET: usize = 32;
const MAX_PENDING_TUN_DOWNLINK_AGE: Duration = Duration::from_secs(5);
const MAX_MASQUE_DOWNLINK_RESPONSES: usize = 128;
const MAX_MASQUE_DOWNLINK_RESPONSE_BYTES: usize = 192 * 1024;

include!("parts/config.rs");
include!("parts/bootstrap.rs");
include!("parts/runtime_admin.rs");
include!("parts/live_auth.rs");
include!("parts/live_state.rs");
include!("parts/tun_path.rs");
include!("parts/qkey_issue.rs");
include!("parts/dns_signals.rs");
include!("parts/runtime_impl.rs");
include!("parts/tests_inline.rs");
