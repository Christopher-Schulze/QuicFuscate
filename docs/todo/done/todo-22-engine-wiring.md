# TODO #22: Engine Wiring - Core Integration

**Status**: In Progress (Started 2025-12-26)
**Priority**: Critical
**Effort**: Large (5-7 days)
**Depends On**: TODO #21 (Complete)

---

## Goal

Wire the `QuicFuscateEngine` skeleton to actual subsystems so that:
1. `start()` opens TUN interface and initializes all subsystems
2. `connect()` establishes real QUIC connection with TLS handshake
3. Packet I/O flows: App -> TUN -> QUIC -> Network (and reverse)
4. Stealth obfuscation and FEC are active in the packet path

---

## Architecture Overview

```
QuicFuscateEngine

  Core state:
  - EngineConfig
  - EngineState
  - Callbacks

  Subsystem handles:
  - tun: Option<TunInterface> (Phase 1)
  - connection: Option<QuicFuscateConnection> (Phase 2)
  - stealth: Arc<StealthManager> (Phase 3)
  - fec: Arc<AdaptiveFec> (Phase 3)
  - pool: Arc<MemoryPool> (Phase 1)

  Async I/O tasks:
  - tun_reader: JoinHandle<()> (Phase 4)
  - tun_writer: JoinHandle<()> (Phase 4)
  - quic_sender: JoinHandle<()> (Phase 4)
  - quic_receiver: JoinHandle<()> (Phase 4)
  - stats_updater: JoinHandle<()> (Phase 5)
```

---

## Implementation Plan

### Phase 1: TUN Integration

**Goal**: `start()` opens TUN, `stop()` closes it.

**Files to modify**:
- `src/engine/engine.rs` - Add TUN field, wire start/stop

**Code Changes**:

```rust
// Add to QuicFuscateEngine struct
pub struct QuicFuscateEngine {
    config: EngineConfig,
    state: EngineState,
    stats: Arc<EngineStats>,
    callbacks: Vec<Box<dyn EngineCallback>>,
    
    // Subsystem handles
    tun: Option<TunInterface>,
    pool: Option<Arc<crate::optimize::MemoryPool>>,
}

// Modify start()
pub fn start(&mut self) -> Result<(), EngineError> {
    // ... state validation ...
    
    // Initialize memory pool
    let pool_config = &self.config.optimization;
    let pool = Arc::new(crate::optimize::MemoryPool::new(
        pool_config.memory_pool_size,
        pool_config.memory_pool_alignment,
    ));
    self.pool = Some(pool.clone());
    
    // Open TUN interface (if enabled)
    if self.config.interface.interface_type == InterfaceType::Tun {
        let tun_name = if self.config.interface.tun_name.is_empty() {
            None
        } else {
            Some(self.config.interface.tun_name.as_str())
        };
        
        let tun = TunInterface::open(tun_name, pool)?;
        self.tun = Some(tun);
    }
    
    self.set_state(EngineState::Running);
    Ok(())
}

// Modify stop()
pub fn stop(&mut self) -> Result<(), EngineError> {
    // Close TUN
    if let Some(tun) = self.tun.take() {
        drop(tun); // TunInterface::drop closes the device
    }
    
    // Release pool
    self.pool = None;
    
    self.set_state(EngineState::Stopped);
    Ok(())
}
```

**Work Items**:
- [x] Add `tun` and `pool` fields to `QuicFuscateEngine` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Import `TunInterface` from `crate::interface` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Initialize pool in `start()` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Open TUN in `start()` based on config (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Close TUN in `stop()` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Add TUN open/close to callbacks (new event) (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Test on macOS/Linux (Closed as superseded by current runtime architecture, 2026-02-12)

---

### Phase 2: QUIC Connection Integration

**Goal**: `connect()` establishes real QUIC connection.

**Key Discovery**: `QuicFuscateConnection::new_client()` in `core.rs` already handles:
- QUIC connection creation
- StealthManager initialization
- FEC configuration
- TLS/SNI configuration
- XDP socket creation (optional)

**Files to modify**:
- `src/implementations/client/mod.rs` - Add connection field, integrate with core.rs
- `src/implementations/client/connection.rs` - Connection wrapper

**Code Changes**:

```rust
// src/implementations/client/connection.rs

use std::net::SocketAddr;
use std::sync::Arc;

use crate::core::{QuicFuscateConnection, ConnectionParams};
use crate::fec::FecConfig;
use crate::stealth::StealthConfig;
use crate::optimize::OptimizeConfig;
use crate::transport::Config as TransportConfig;
use crate::engine::{EngineConfig, EngineError};

/// Client connection wrapper.
pub struct ClientConnection {
    inner: QuicFuscateConnection,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl ClientConnection {
    /// Create a new client connection.
    pub fn connect(config: &EngineConfig) -> Result<Self, EngineError> {
        // Parse addresses
        let remote_addr: SocketAddr = config.connection.remote.parse()
            .map_err(|e| EngineError::Config(format!("Invalid remote: {}", e)))?;
        let local_addr: SocketAddr = if config.connection.local.is_empty() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            config.connection.local.parse()
                .map_err(|e| EngineError::Config(format!("Invalid local: {}", e)))?
        };
        
        // Build transport config
        let mut transport_config = TransportConfig::new().unwrap();
        transport_config.set_max_idle_timeout(config.transport.max_idle_timeout);
        transport_config.set_initial_max_data(config.transport.initial_max_data);
        
        // Build stealth config from EngineConfig
        let stealth_config = StealthConfig::from(&config.stealth);
        
        // Build FEC config
        let fec_config = FecConfig::from(&config.fec);
        
        // Build optimization config
        let opt_config = OptimizeConfig::from(&config.optimization);
        
        // Create QUIC connection
        let conn = QuicFuscateConnection::new_client(
            &config.connection.sni,
            local_addr,
            remote_addr,
            transport_config,
            stealth_config,
            fec_config,
            opt_config,
            false, // use_utls
        ).map_err(|e| EngineError::Connection(e))?;
        
        Ok(Self {
            inner: conn,
            remote_addr,
            local_addr,
        })
    }
    
    /// Send data.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, EngineError> {
        self.inner.send(buf)
            .map_err(|e| EngineError::Connection(format!("{:?}", e)))
    }
    
    /// Receive data.
    pub fn recv(&mut self, data: &[u8]) -> Result<usize, EngineError> {
        self.inner.recv(data)
            .map_err(|e| EngineError::Connection(format!("{:?}", e)))
    }
    
    /// Get peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote_addr
    }
    
    /// Get stealth manager.
    pub fn stealth_manager(&self) -> Arc<crate::stealth::StealthManager> {
        self.inner.stealth_manager()
    }
}
```

**Work Items**:
- [x] Add `connection` field to `ClientRuntime` OK
- [x] Create `src/implementations/client/connection.rs` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Wire `connect()` in `ClientRuntime` to use `ClientConnection` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Add config converters: `StealthConfig::from(&StealthSection)` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Add config converters: `FecConfig::from(&FecSection)` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Add config converters: `OptimizeConfig::from(&OptimizationConfig)` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Handle TLS errors with proper callbacks (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Implement `disconnect()` with CONNECTION_CLOSE (Closed as superseded by current runtime architecture, 2026-02-12)

---

### Phase 3: Stealth and FEC Integration

**Goal**: Wire StealthManager and AdaptiveFec into the packet path.

**Files to modify**:
- `src/engine/engine.rs` - Add stealth/fec fields, initialize in start()

**Code Changes**:

```rust
// Add to QuicFuscateEngine struct
stealth: Option<Arc<StealthManager>>,
fec: Option<Arc<Mutex<AdaptiveFec>>>,

// In start()
pub fn start(&mut self) -> Result<(), EngineError> {
    // ... TUN init ...
    
    // Initialize StealthManager from config
    let stealth_config = StealthConfig::from(&self.config.stealth);
    let stealth = Arc::new(StealthManager::new(stealth_config));
    self.stealth = Some(stealth);
    
    // Initialize FEC from config
    let fec_config = FecConfig::from(&self.config.fec);
    let fec = Arc::new(Mutex::new(AdaptiveFec::new(fec_config)));
    self.fec = Some(fec);
    
    // ...
}
```

**Work Items**:
- [x] Add `stealth` and `fec` fields (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create `StealthConfig::from(&StealthSection)` converter (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create `FecConfig::from(&FecSection)` converter (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Initialize in `start()` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Wire into packet processing (Phase 4) (Closed as superseded by current runtime architecture, 2026-02-12)

---

### Phase 4: Async Packet I/O Loop

**Goal**: Bidirectional packet flow between TUN and QUIC.

**Architecture**:

```
Outbound (TUN -> network):
TUN Device -> Stealth (obfuscate) -> FEC (encode) -> QUIC (send) -> Network

Inbound (network -> TUN):
Network -> QUIC (recv) -> FEC (decode) -> Stealth (deobfuscate) -> TUN Device
```

**Code Changes**:

```rust
// Add I/O task handles
io_tasks: Option<IoTasks>,

struct IoTasks {
    tun_to_quic: JoinHandle<()>,
    quic_to_tun: JoinHandle<()>,
    shutdown: broadcast::Sender<()>,
}

impl QuicFuscateEngine {
    fn spawn_io_tasks(&mut self) {
        let (shutdown_tx, _) = broadcast::channel(1);
        
        let tun = self.tun.clone().unwrap();
        let conn = self.connection.clone().unwrap();
        let stealth = self.stealth.clone().unwrap();
        let fec = self.fec.clone().unwrap();
        let stats = self.stats.clone();
        
        // TUN -> QUIC task
        let tun_to_quic = {
            let mut shutdown_rx = shutdown_tx.subscribe();
            let tun = tun.clone();
            let conn = conn.clone();
            let stealth = stealth.clone();
            let fec = fec.clone();
            let stats = stats.clone();
            
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => break,
                        result = tun.read_packet() => {
                            if let Ok(packet) = result {
                                // Apply stealth obfuscation
                                let obfuscated = stealth.obfuscate(&packet);
                                
                                // Apply FEC encoding
                                let encoded = fec.lock().await.encode(&obfuscated);
                                
                                // Send via QUIC
                                conn.lock().await.send(&encoded).await.ok();
                                
                                // Update stats
                                stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                                stats.bytes_sent.fetch_add(packet.len() as u64, Ordering::Relaxed);
                            }
                        }
                    }
                }
            })
        };
        
        // QUIC -> TUN task (similar structure, reverse direction)
        let quic_to_tun = tokio::spawn(async move { /* ... */ });
        
        self.io_tasks = Some(IoTasks {
            tun_to_quic,
            quic_to_tun,
            shutdown: shutdown_tx,
        });
    }
    
    fn stop_io_tasks(&mut self) {
        if let Some(tasks) = self.io_tasks.take() {
            let _ = tasks.shutdown.send(());
            // Tasks will exit on next iteration
        }
    }
}
```

**Work Items**:
- [x] Add `IoTasks` struct with JoinHandles (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Implement `spawn_io_tasks()` in `connect()` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Implement TUN -> QUIC pipeline (read, obfuscate, encode, send) (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Implement QUIC -> TUN pipeline (recv, decode, deobfuscate, write) (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Add shutdown channel for graceful stop (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Wire stats updates in I/O loops (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Handle packet errors without crashing (Closed as superseded by current runtime architecture, 2026-02-12)

---

### Phase 5: Tokio Runtime Integration

**Goal**: Non-blocking async I/O with proper runtime management.

**Options**:

1. **Engine owns runtime** (simpler, self-contained)
```rust
pub struct QuicFuscateEngine {
    runtime: Option<Runtime>,
    // ...
}

impl QuicFuscateEngine {
    pub fn start(&mut self) -> Result<(), EngineError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(self.config.optimization.num_worker_threads)
            .enable_all()
            .build()?;
        self.runtime = Some(runtime);
        // ...
    }
    
    pub fn connect(&mut self) -> Result<(), EngineError> {
        let runtime = self.runtime.as_ref().unwrap();
        runtime.block_on(self.connect_async())
    }
}
```

2. **Engine uses external runtime** (more flexible)
```rust
impl QuicFuscateEngine {
    pub async fn start(&mut self) -> Result<(), EngineError> { /* ... */ }
    pub async fn connect(&mut self) -> Result<(), EngineError> { /* ... */ }
}
```

**Recommendation**: Option 1 for simplicity - engine manages its own runtime.

**Work Items**:
- [x] Add `runtime` field to `QuicFuscateEngine` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create runtime in `start()` with configured worker threads (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Shutdown runtime in `stop()` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Wrap async operations with `runtime.block_on()` for sync API (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Optional: Add `*_async()` variants for async callers (Closed as superseded by current runtime architecture, 2026-02-12)

---

### Phase 6: End-to-End Testing

**Goal**: Verify full client mode functionality.

**Test Setup**:

```
Test Client (QuicFuscateEngine + TUN: qf0) <-> Test Server (Simple QUIC echo, localhost:4433)
```

**Test Cases**:

1. **Basic Connectivity**
   - Engine starts successfully
   - TUN device created
   - QUIC connection established
   - Engine stops cleanly

2. **Packet Flow**
   - Send ICMP ping through TUN
   - Verify packet reaches test server
   - Verify response flows back

3. **Stealth Verification**
   - Enable stealth mode
   - Capture packets with tcpdump
   - Verify obfuscation applied

4. **FEC Verification**
   - Enable FEC
   - Simulate packet loss
   - Verify recovery works

5. **Error Handling**
   - Server unavailable -> proper error callback
   - Connection timeout -> auto-reconnect option
   - TUN permission denied -> clear error message

**Work Items**:
- [x] Create test QUIC echo server in `examples/` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create integration test for basic connectivity (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create integration test for packet flow (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create integration test for stealth (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create integration test for FEC (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Create integration test for error cases (Closed as superseded by current runtime architecture, 2026-02-12)

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/engine/engine.rs` | Add subsystem fields, wire lifecycle methods, I/O tasks |
| `src/engine/mod.rs` | Add re-exports for new types |
| `src/engine/io.rs` | Packet I/O loop implementation |
| `src/engine/config.rs` | Add converter methods to existing configs |
| `examples/test_server.rs` | Test server for E2E testing |
| `scripts/tests/rust/rt-engine-e2e.rs` | Integration tests |

---

## Success Criteria

- [x] `engine.start()` creates TUN device visible in `ifconfig` (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] `engine.connect()` establishes verified QUIC connection (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Packets sent to TUN arrive at server (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Packets from server arrive at TUN (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Stealth obfuscation visible in packet captures (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] FEC protects against simulated packet loss (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Stats accurately reflect traffic (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Callbacks fire for all events (Closed as superseded by current runtime architecture, 2026-02-12)
- [x] Clean shutdown with no resource leaks (Closed as superseded by current runtime architecture, 2026-02-12)

---

## Estimated Effort

| Phase | Days | Risk |
|-------|------|------|
| Phase 1: TUN | 0.5 | Low |
| Phase 2: QUIC | 1.5 | Medium |
| Phase 3: Stealth/FEC | 1 | Low |
| Phase 4: I/O Loop | 1.5 | High |
| Phase 5: Tokio | 0.5 | Low |
| Phase 6: Testing | 1 | Medium |
| **Total** | **6 days** | |
