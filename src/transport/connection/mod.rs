use super::{
    cid, config::Config, config::PmtuPolicy, config::TrafficAnalysisDefense, frames, packet,
    pnspace, recovery, udpfast, ConnectionId, EcnCounts, EcnMark, FecControlDelta, Frame,
    PacketType, PathStats, RecvInfo, SendInfo, Stats, Stream, TransportObserver, INITIAL_WINDOW,
    MAX_STREAM_SIZE, MIN_CLIENT_INITIAL_LEN,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::aead::AeadSeal;
use crate::optimize::{prefetch, PrefetchHint};

const MAX_RX_KEY_UPDATE_ADVANCE: usize = 4;
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(3);
const MIGRATION_COOLDOWN: Duration = Duration::from_millis(750);
const MAX_STREAM_RETRANSMIT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_ORIGINAL_TRANSMISSIONS: usize = 16 * 1024;
const MAX_STREAM_TRANSMISSIONS: usize = 2 * MAX_STREAM_ORIGINAL_TRANSMISSIONS;
const MAX_STREAM_LOST_PACKET_HISTORY: usize = 32;


include!("parts/pmtu.rs");
include!("parts/types.rs");
include!("parts/impl_lifecycle.rs");
include!("parts/impl_recv.rs");
include!("parts/impl_send.rs");
include!("parts/impl_api.rs");
include!("parts/bench.rs");
include!("parts/tests.rs");
