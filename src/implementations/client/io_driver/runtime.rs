use super::*;

const ASSIGNMENT_CLOSE_SEND_TIMEOUT: Duration = Duration::from_millis(500);

/// Borrowed view of the TUN descriptor so `AsyncFd` can register it for
/// readiness without taking ownership of the device.
#[cfg(target_os = "linux")]
struct TunFdRef(std::os::fd::RawFd);

#[cfg(target_os = "linux")]
impl std::os::fd::AsRawFd for TunFdRef {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

#[cfg(target_os = "linux")]
type TunReadable = tokio::io::unix::AsyncFd<TunFdRef>;

fn masque_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("QUICFUSCATE_MASQUE_TRACE").is_some())
}

impl IoDriver {
    #[inline]
    pub(super) fn normalized_batch_size(&self) -> usize {
        let cap = if self.wide_batch_cpu { 256 } else { 128 };
        self.config.batch_size.clamp(1, cap)
    }

    /// Create a new I/O driver.
    pub fn new(config: IoDriverConfig) -> Self {
        Self::new_with_clock(config, &ProtocolClock::default())
    }

    /// Create an I/O driver bound to an explicit protocol clock.
    pub fn new_with_clock(config: IoDriverConfig, clock: &ProtocolClock) -> Self {
        #[cfg(target_os = "linux")]
        let hotpath_adapter: Arc<dyn IoHotpathAdapter> =
            Arc::new(SystemIoHotpathAdapter::default());
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        let (uring_sender, uring_available) = {
            let worker = if crate::optimize::uring_batch::env_disabled() {
                None
            } else {
                crate::optimize::uring_batch::UringBatchWorker::with_defaults()
            };
            let available = worker.is_some();
            if available {
                log::info!("io_uring batch worker initialised");
            }
            (worker, available)
        };
        let profile = crate::optimize::FeatureDetector::instance().profile();
        crate::optimize::telemetry::publish_cpu_profile_mask(profile);
        let wide_batch_cpu = profile_prefers_wide_batches(profile);
        Self {
            config,
            clock: clock.clone(),
            shutdown: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(IoDriverStats::default()),
            #[cfg(target_os = "linux")]
            hotpath_adapter,
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            uring_worker: uring_sender,
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            uring_available,
            #[cfg(target_os = "linux")]
            flush_scratch: tokio::sync::Mutex::new(FlushScratch::default()),
            wide_batch_cpu,
            #[cfg(test)]
            assignment_receive_barrier: None,
        }
    }

    #[cfg(all(target_os = "linux", test))]
    pub(super) fn with_hotpath_adapter(
        config: IoDriverConfig,
        hotpath_adapter: Arc<dyn IoHotpathAdapter>,
    ) -> Self {
        let mut driver = Self::new(config);
        driver.hotpath_adapter = hotpath_adapter;
        driver
    }

    /// True when io_uring was successfully initialised at construction.
    /// Cached to avoid a Mutex lock on every hot-path iteration.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    #[inline(always)]
    fn has_uring(&self) -> bool {
        self.uring_available
            && self.uring_worker.as_ref().is_some_and(|worker| worker.is_available())
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        if let Some(worker) = self.uring_worker.as_ref() {
            worker.request_shutdown();
        }
    }

    /// Join the owned io_uring blocking worker after its async loops stopped.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    pub fn join_io_uring_worker(&self) -> Result<(), String> {
        self.uring_worker.as_ref().map_or(Ok(()), |worker| worker.join())
    }

    /// Get stats reference.
    pub fn stats(&self) -> &Arc<IoDriverStats> {
        &self.stats
    }

    /// Record a terminal data-plane fault that was detected by a task wrapper
    /// rather than inside one of the driver loops.
    pub fn record_data_plane_fault(&self) {
        self.stats.data_plane_faults.fetch_add(1, Ordering::Relaxed);
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
    }

    fn data_plane_error(&self, fault: DataPlaneFault) -> EngineError {
        EngineError::DataPlane(fault)
    }

    fn transport_send_error(&self, component: &str, error: impl std::fmt::Display) -> EngineError {
        self.data_plane_error(DataPlaneFault::TransportSend {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    fn transport_receive_error(
        &self,
        component: &str,
        error: impl std::fmt::Display,
    ) -> EngineError {
        self.data_plane_error(DataPlaneFault::TransportReceive {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    fn tun_write_error(&self, component: &str, error: impl std::fmt::Display) -> EngineError {
        self.data_plane_error(DataPlaneFault::TunWrite {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    #[cfg(target_os = "linux")]
    fn reader_stopped_error(&self, component: &str, error: impl std::fmt::Display) -> EngineError {
        self.data_plane_error(DataPlaneFault::ReaderStopped {
            component: component.to_string(),
            error: error.to_string(),
        })
    }

    /// Compute the next inbound poll timeout, capping it by the connection's
    /// earliest send deadline (pacing/stealth release or recovery/PTO timer).
    fn recv_timeout(&self, conn: &Arc<parking_lot::Mutex<ClientDataPlane>>) -> Duration {
        let base = Duration::from_millis(200);
        let deadline = { conn.lock().next_send_deadline() };
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(self.clock.now());
            if remaining.is_zero() {
                return Duration::from_millis(1);
            }
            return remaining.min(base).max(Duration::from_millis(1));
        }
        base
    }

    /// Blocking receive of one wire message. On Linux this is `recvmsg` with
    /// `UDP_GRO` ancillary parsing - required once GRO is enabled, because a
    /// kernel-coalesced buffer reports its segment size only via the control
    /// channel (TODO-923). Returns `(len, gso_size)`; `gso_size == 0` marks a
    /// plain single datagram.
    #[cfg(target_os = "linux")]
    async fn recv_wire_datagram(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, u16)> {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        socket
            .async_io(tokio::io::Interest::READABLE, || {
                qf_transport_udp::recv_msg_gro(fd, buf, false).map(|(len, _, gso)| (len, gso))
            })
            .await
    }

    #[cfg(not(target_os = "linux"))]
    async fn recv_wire_datagram(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, u16)> {
        socket.recv(buf).await.map(|len| (len, 0))
    }

    /// Non-blocking receive of one wire message; same GRO contract as
    /// [`recv_wire_datagram`].
    #[cfg(target_os = "linux")]
    fn try_recv_wire_datagram(socket: &UdpSocket, buf: &mut [u8]) -> std::io::Result<(usize, u16)> {
        use std::os::unix::io::AsRawFd;
        qf_transport_udp::recv_msg_gro(socket.as_raw_fd(), buf, false)
            .map(|(len, _, gso)| (len, gso))
    }

    #[cfg(not(target_os = "linux"))]
    fn try_recv_wire_datagram(socket: &UdpSocket, buf: &mut [u8]) -> std::io::Result<(usize, u16)> {
        socket.try_recv(buf).map(|len| (len, 0))
    }

    /// Record one wire message as `(offset, len)` spans into the flat recv
    /// buffer, splitting a kernel-coalesced (`gso_size > 0`) buffer into
    /// per-datagram spans in wire order. Zero-copy: no payload bytes move.
    fn emit_wire_spans(base: usize, len: usize, gso_size: u16, spans: &mut Vec<(usize, usize)>) {
        let gso = gso_size as usize;
        let mut offset = 0usize;
        while offset < len {
            let seg_len = if gso == 0 { len } else { (len - offset).min(gso) };
            spans.push((base + offset, seg_len));
            offset += seg_len;
            if gso == 0 {
                break;
            }
        }
    }

    /// Flush any pending outgoing packets (ACKs, PTO probes, etc.) produced by
    /// the QUIC connection.  Used by the inbound loop so probes are not held
    /// back until the outbound TUN loop wakes.
    async fn flush_outbound(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: &Arc<UdpSocket>,
        out: &mut [u8],
    ) -> Result<(), EngineError> {
        // Linux: drain into the flat scratch and emit each burst with one
        // sendmmsg (falling back to sequential sends). ACK/PTO bursts no
        // longer cost one syscall per datagram.
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            const FLUSH_BATCH_PACKETS: usize = 16;
            const FLUSH_BATCH_BYTES: usize = 256 * 1024;

            let mut scratch = self.flush_scratch.lock().await;
            loop {
                scratch.flat.clear();
                scratch.spans.clear();
                let mut drained = false;
                while scratch.spans.len() < FLUSH_BATCH_PACKETS
                    && (scratch.flat.is_empty()
                        || scratch.flat.len() + out.len() <= FLUSH_BATCH_BYTES)
                {
                    let written = {
                        let mut conn_guard = conn.lock();
                        let send_result = conn_guard.send(&mut *out);
                        match &send_result {
                            Ok(0) => {
                                drained = true;
                                break;
                            }
                            Ok(written) => *written,
                            Err(EngineError::Connection(msg))
                                if msg == "Connection done" || msg == "Buffer too short" =>
                            {
                                // Transient under netem impairment - see the
                                // portable arm below.
                                drained = true;
                                break;
                            }
                            Err(e) => {
                                log::debug!("Connection send error during flush: {:?}", e);
                                return Err(
                                    self.transport_send_error("client inbound flush", e.clone())
                                );
                            }
                        }
                    };
                    let start = scratch.flat.len();
                    scratch.flat.extend_from_slice(&out[..written]);
                    scratch.spans.push((start, written));
                }
                if scratch.spans.is_empty() {
                    return Ok(());
                }

                // sendmmsg emits a contiguous prefix; the tail falls back to
                // sequential sends with identical error semantics.
                let mut sent_prefix = 0usize;
                if scratch.spans.len() > 1 {
                    let refs: smallvec::SmallVec<[&[u8]; 16]> = scratch
                        .spans
                        .iter()
                        .map(|&(start, len)| &scratch.flat[start..start + len])
                        .collect();
                    match try_sendmmsg_batch(
                        self.hotpath_adapter.as_ref(),
                        socket.as_raw_fd(),
                        OutboundDispatch::SendmmsgBatch,
                        &refs,
                    ) {
                        Ok(n) => {
                            sent_prefix = n.min(refs.len());
                            crate::optimize::telemetry::IO_DRIVER_SENDMMSG_CALLS
                                .fetch_add(1, Ordering::Relaxed);
                            crate::optimize::telemetry::IO_DRIVER_SENDMMSG_PACKETS
                                .fetch_add(sent_prefix as u64, Ordering::Relaxed);
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::InvalidData | std::io::ErrorKind::WriteZero
                            ) =>
                        {
                            return Err(self
                                .transport_send_error("client flush UDP sendmmsg result", error));
                        }
                        Err(error) => {
                            log::debug!("flush sendmmsg fallback: {}", error);
                        }
                    }
                }

                // Telemetry accumulates into locals across both loops and
                // lands as one atomic batch instead of three RMWs per packet.
                let mut flush_bytes = 0u64;
                let mut flush_packets = 0u64;
                for &(_, len) in &scratch.spans[..sent_prefix] {
                    flush_bytes += len as u64;
                    flush_packets += 1;
                }
                for &(start, len) in &scratch.spans[sent_prefix..] {
                    let payload = &scratch.flat[start..start + len];
                    if let Err(e) = socket.send(payload).await {
                        log::warn!("UDP send error during outbound flush: {}", e);
                        return Err(self.transport_send_error("client inbound UDP flush", e));
                    }
                    flush_bytes += len as u64;
                    flush_packets += 1;
                }
                if flush_packets > 0 {
                    self.stats.udp_packets_sent.fetch_add(flush_packets, Ordering::Relaxed);
                    let global = crate::instrumentation::global();
                    global.transport.record_bytes_out(flush_bytes);
                    global.transport.record_packets_out(flush_packets);
                }

                if drained {
                    return Ok(());
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        loop {
            let written = {
                let mut conn_guard = conn.lock();
                let send_result = conn_guard.send(&mut *out);
                match &send_result {
                    Ok(0) => break,
                    Ok(written) => *written,
                    Err(EngineError::Connection(msg))
                        if msg == "Connection done" || msg == "Buffer too short" =>
                    {
                        // Under netem impairment the QUIC packet builder may not have
                        // enough congestion window or MTU budget to produce a packet in
                        // this iteration. This is transient: break and retry on the next
                        // loop tick rather than dropping the circuit.
                        break;
                    }
                    Err(e) => {
                        log::debug!("Connection send error during flush: {:?}", e);
                        return Err(self.transport_send_error("client inbound flush", e.clone()));
                    }
                }
            };

            if let Err(e) = socket.send(&out[..written]).await {
                log::warn!("UDP send error during outbound flush: {}", e);
                return Err(self.transport_send_error("client inbound UDP flush", e));
            }

            self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
            let global = crate::instrumentation::global();
            global.transport.record_bytes_out(written as u64);
            global.transport.record_packet_out();
        }
        #[cfg(not(target_os = "linux"))]
        Ok(())
    }

    /// Emit only the physical hop's already queued terminal close. Circuit
    /// drive and ordinary outbound queues cannot delay this last packet.
    async fn flush_physical_close(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: &Arc<UdpSocket>,
        out: &mut [u8],
    ) -> Result<bool, EngineError> {
        let length = {
            let mut guard = conn.lock();
            match guard.physical_mut().send(out) {
                Ok(length) => length,
                Err(crate::error::ConnectionError::Done) => return Ok(false),
                Err(error) => {
                    return Err(self.transport_send_error("client assignment close seal", error))
                }
            }
        };
        if length == 0 {
            return Ok(false);
        }
        let sent = tokio::time::timeout(ASSIGNMENT_CLOSE_SEND_TIMEOUT, socket.send(&out[..length]))
            .await
            .map_err(|_| {
                self.transport_send_error("client assignment close UDP send", "send timed out")
            })?
            .map_err(|error| {
                self.transport_send_error("client assignment close UDP send", error)
            })?;
        if sent != length {
            return Err(self.transport_send_error(
                "client assignment close UDP send",
                format!("short send: {sent} of {length} bytes"),
            ));
        }
        self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
        let global = crate::instrumentation::global();
        global.transport.record_bytes_out(length as u64);
        global.transport.record_packet_out();
        Ok(true)
    }

    /// Drive QUIC and H3 until the authenticated server assignment arrives.
    /// No TUN handle is needed or opened during this phase.
    pub async fn negotiate_assignment(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: &Arc<UdpSocket>,
        generation: u64,
        deadline: Instant,
    ) -> Result<crate::control_plane::ClientAssignment, EngineError> {
        let reception = Arc::new(parking_lot::Mutex::new({
            let connect_ip_required = conn.lock().is_circuit();
            let reception = if connect_ip_required {
                crate::control_plane::AssignmentReception::new_connect_ip(generation)
            } else {
                crate::control_plane::AssignmentReception::new(generation)
            };
            reception.map_err(|error| EngineError::Connection(error.to_string()))?
        }));
        {
            let mut guard = conn.lock();
            guard.set_client_connection_generation(generation);
        }

        let mut recv_buf = vec![0u8; 65_535];
        let mut send_buf = vec![0u8; 65_535];
        let mut control_started = false;
        while self.clock.now() < deadline {
            self.flush_outbound(conn, socket, &mut send_buf).await?;
            let (failure, assignment) = {
                let state = reception.lock();
                (state.failure().cloned(), state.assignment().cloned())
            };
            if let Some(error) = failure {
                conn.lock().mark_failed();
                return Err(EngineError::Connection(format!(
                    "client assignment control plane rejected: {error}"
                )));
            }
            if let Some(assignment) = assignment {
                if conn.lock().masque_tunnel_established() {
                    let mut guard = conn.lock();
                    guard.finalize_authenticated_assignment().map_err(|error| {
                        self.transport_send_error(
                            "client assignment private packet-protection control",
                            error,
                        )
                    })?;
                    guard.mark_ready();
                    return Ok(assignment);
                }
            }

            let established = { conn.lock().is_established() };
            if established && !control_started {
                // The circuit is fully established only after every pending hop
                // was activated, so `exit_mut()` now resolves to the real exit
                // hop. Install the control capsule sink here, right before the
                // tunnel opens: installing it earlier would bind the sink to the
                // entry hop, whose connection never carries CONNECT-IP control
                // capsules, and leave the later-activated exit hop without a sink.
                let callback_state = Arc::clone(&reception);
                let mut guard = conn.lock();
                guard.set_masque_control_cb(Arc::new(std::sync::Mutex::new(Box::new(
                    move |capsule_type: u64, payload: &[u8]| {
                        let mut state = callback_state.lock();
                        state.receive(capsule_type, payload);
                        if masque_trace_enabled() {
                            log::info!(
                                "received MASQUE control capsule type={} bytes={} assignment_ready={} failed={}",
                                capsule_type,
                                payload.len(),
                                state.assignment().is_some(),
                                state.failure().is_some()
                            );
                        }
                    },
                ))));
                let stream_id = guard
                    .begin_masque_control_tunnel()
                    .map_err(|error| EngineError::Connection(error.to_string()))?;
                control_started = true;
                if masque_trace_enabled() {
                    log::info!("started MASQUE assignment control tunnel stream={stream_id}");
                }
                continue;
            }

            let remaining = deadline.saturating_duration_since(self.clock.now());
            let wait = remaining.min(Duration::from_millis(100));
            if wait.is_zero() {
                break;
            }
            #[cfg(test)]
            if let Some(barrier) = &self.assignment_receive_barrier {
                barrier.notify_one();
            }
            let mut terminal_receive_error = None;
            match tokio::time::timeout(wait, socket.recv(&mut recv_buf)).await {
                Ok(Ok(length)) if length > 0 => {
                    let mut guard = conn.lock();
                    let recv_result = guard.recv_mut(&mut recv_buf[..length]);
                    if guard.physical().conn.is_closed() {
                        terminal_receive_error = recv_result.err();
                    } else {
                        match &recv_result {
                            Ok(_) => {}
                            Err(EngineError::Connection(msg))
                                if msg == "Connection done" || msg == "Buffer too short" =>
                            {
                                // Under netem impairment (loss + reorder) a truncated or
                                // coalesced packet fragment can reach the QUIC parser before
                                // the complete datagram arrives. Both are transient while open.
                            }
                            Err(_) => {
                                Err(self.transport_receive_error(
                                    "client assignment QUIC receive",
                                    recv_result.unwrap_err(),
                                ))?;
                            }
                        }
                        if control_started {
                            guard.poll_http3().map_err(|error| {
                                self.transport_receive_error("client assignment H3 poll", error)
                            })?;
                        }
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    return Err(
                        self.transport_receive_error("client assignment UDP receive", error)
                    );
                }
                Err(_) => {}
            }
            if conn.lock().physical().conn.is_closed() {
                let original = terminal_receive_error.unwrap_or_else(|| {
                    let cause = conn
                        .lock()
                        .physical()
                        .conn
                        .error()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "transport closed".to_string());
                    EngineError::Connection(format!(
                        "client closed before server assignment: {cause}"
                    ))
                });
                let close_send = self.flush_physical_close(conn, socket, &mut send_buf).await;
                conn.lock().mark_failed();
                if let Err(send_error) = close_send {
                    return Err(self.transport_send_error(
                        "client assignment terminal close",
                        format!("{original}; close send failed: {send_error}"),
                    ));
                }
                return Err(original);
            }
            if conn.lock().is_closed() {
                conn.lock().mark_failed();
                return Err(EngineError::Connection(
                    "client closed before receiving server assignment".to_string(),
                ));
            }
        }
        Err(EngineError::Connection(
            "timed out waiting for authenticated server assignment".to_string(),
        ))
    }

    /// Keep an authenticated replacement circuit live without attaching it to TUN.
    ///
    /// The standby owns one bounded receive/flush loop. Any unsolicited tunnel payload is
    /// discarded rather than queued indefinitely, while ACK, PTO, key-update, and close traffic
    /// continues to be serviced until promotion or teardown.
    pub async fn run_standby(
        &self,
        conn: Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: Arc<UdpSocket>,
        ingress: ClientTunnelIngress,
    ) -> Result<(), EngineError> {
        let mut recv_buf = vec![0u8; 65_535];
        let mut send_buf = vec![0u8; 65_535];
        while !self.shutdown.load(Ordering::Relaxed) {
            let timeout = self.recv_timeout(&conn);
            match tokio::time::timeout(timeout, socket.recv(&mut recv_buf)).await {
                Err(_) => {}
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(Err(error)) => {
                    return Err(self.transport_receive_error("client standby UDP receive", error));
                }
                Ok(Ok(length)) if length > 0 => {
                    self.stats.udp_packets_received.fetch_add(1, Ordering::Relaxed);
                    let global = crate::instrumentation::global();
                    global.transport.record_bytes_in(length as u64);
                    global.transport.record_packet_in();
                    conn.lock().recv_mut(&mut recv_buf[..length]).map_err(|error| {
                        self.transport_receive_error("client standby QUIC receive", error)
                    })?;
                    self.poll_http3_to_ingress(&conn, &ingress)?;
                    let _discarded = ingress.drain();
                }
                Ok(Ok(_)) => {}
            }
            self.flush_outbound(&conn, &socket, &mut send_buf).await?;
            if conn.lock().is_closed() {
                return Err(EngineError::Connection(
                    "prebuilt standby circuit closed before promotion".to_string(),
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn poll_connection_send(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        out: &mut [u8],
    ) -> Result<Option<usize>, EngineError> {
        let mut conn_guard = conn.lock();
        match conn_guard.send(out) {
            Ok(0) => Ok(None),
            Ok(written) => Ok(Some(written)),
            Err(error) => Err(self.transport_send_error("client outbound connection send", error)),
        }
    }

    #[cfg(target_os = "linux")]
    async fn enqueue_tun_datagram(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: &Arc<UdpSocket>,
        out: &mut [u8],
        tunnel_stream_id: u64,
        packet: &[u8],
    ) -> Result<(), EngineError> {
        loop {
            let result = {
                let mut conn_guard = conn.lock();
                conn_guard.send_tunnel_packet(tunnel_stream_id, packet)
            };
            match result {
                Ok(()) => return Ok(()),
                Err(EngineError::Backpressure) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    // A full QUIC DATAGRAM queue can only drain when the
                    // connection emits packets. Flush that output before
                    // retrying so backpressure cannot become an infinite
                    // sleep loop.
                    self.flush_outbound(conn, socket, out).await?;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => {
                    return Err(self.transport_send_error("client TUN datagram enqueue", error));
                }
            }
        }
    }

    /// Idle wait that wakes as soon as the TUN device is readable or the
    /// connection wants to emit (pacing/stealth/recovery deadline) - replaces
    /// fixed-interval polling so the outbound loop does not burn CPU while
    /// idle. A bounded cap keeps the shutdown flag responsive. Falls back to a
    /// plain sleep when the backend exposes no file descriptor.
    #[cfg(target_os = "linux")]
    async fn wait_tun_idle(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        fallback: Duration,
        tun_readable: &Option<TunReadable>,
    ) {
        if let Some(async_fd) = tun_readable.as_ref() {
            const MAX_IDLE_WAIT: Duration = Duration::from_millis(250);
            let remaining = {
                conn.lock()
                    .next_send_deadline()
                    .map(|deadline| deadline.saturating_duration_since(self.clock.now()))
            }
            .unwrap_or(MAX_IDLE_WAIT)
            .min(MAX_IDLE_WAIT);
            tokio::select! {
                biased;
                ready = async_fd.readable() => {
                    if let Ok(mut guard) = ready {
                        guard.clear_ready();
                    }
                }
                _ = tokio::time::sleep(remaining) => {}
            }
            return;
        }
        tokio::time::sleep(fallback).await;
    }

    /// Run the outbound loop (TUN -> QUIC).
    ///
    /// Reads packets from TUN, processes through Stealth/FEC, sends via UDP.
    pub async fn run_outbound(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: Arc<UdpSocket>,
        tunnel_stream_id: u64,
    ) -> Result<(), EngineError> {
        #[cfg(target_os = "linux")]
        {
            let read_contract = tun.lock().read_contract();
            if read_contract != TunReadContract::NonBlocking {
                return Err(self.reader_stopped_error(
                    "client outbound TUN reader",
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "generic client I/O requires a nonblocking TUN backend; use an owned reader for blocking backends",
                    ),
                ));
            }
        }
        #[cfg(target_os = "linux")]
        let mut send_buf = vec![0u8; 65535];
        #[cfg(target_os = "linux")]
        let batch_cap = self.normalized_batch_size();
        // Flat staging: conn.send writes each datagram straight into the
        // remaining window - no per-packet Vec, no staging copy. Sized to
        // cover a full MTU batch (>=1 MiB bounds pathological 64 KiB packets).
        #[cfg(target_os = "linux")]
        let mut batch_flat: Vec<u8> = vec![0u8; (batch_cap * 2048).max(1 << 20)];
        #[cfg(target_os = "linux")]
        let mut batch_spans: Vec<(usize, usize)> = Vec::with_capacity(batch_cap);
        #[cfg(target_os = "linux")]
        let mut batch_sent: Vec<bool> = Vec::with_capacity(batch_cap);
        // Event-driven idle wait: register the TUN descriptor with the runtime
        // reactor once so the loop below sleeps until the device is readable
        // instead of polling it on a fixed interval.
        #[cfg(target_os = "linux")]
        let tun_readable: Option<TunReadable> = {
            let fd = { tun.lock().tun_raw_fd() };
            fd.and_then(|fd| tokio::io::unix::AsyncFd::new(TunFdRef(fd)).ok())
        };
        #[cfg(target_os = "linux")]
        while !self.shutdown.load(Ordering::Relaxed) {
            // Read from the validated nonblocking TUN backend - returns (block, len).
            let read_result = {
                let tun_guard = tun.lock();
                tun_guard.read_block()
            };
            match read_result {
                Ok((block, len)) if len > 0 => {
                    self.stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);

                    self.enqueue_tun_datagram(
                        &conn,
                        &socket,
                        &mut send_buf,
                        tunnel_stream_id,
                        &block[..len],
                    )
                    .await?;

                    let mut queued = 0usize;
                    let mut watermark = 0usize;
                    batch_spans.clear();
                    while queued < batch_cap && watermark < batch_flat.len() {
                        let written = {
                            let mut conn_guard = conn.lock();
                            match conn_guard.send(&mut batch_flat[watermark..]) {
                                Ok(0) => break,
                                Ok(written) => written,
                                Err(e) => {
                                    log::debug!("Connection send done: {:?}", e);
                                    return Err(
                                        self.transport_send_error("client TUN connection send", e)
                                    );
                                }
                            }
                        };
                        batch_spans.push((watermark, written));
                        watermark += written;
                        queued += 1;
                    }

                    if queued == 0 {
                        continue;
                    }

                    #[cfg(all(target_os = "linux", feature = "io_uring"))]
                    let dispatch = { resolve_outbound_dispatch(queued, self.has_uring()) };
                    #[cfg(target_os = "linux")]
                    {
                        batch_sent.clear();
                        batch_sent.resize(queued, false);
                    }
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::fd::AsRawFd;
                        let socket_fd = socket.as_raw_fd();

                        // io_uring batch path (preferred when available). The
                        // staged slab is handed to the worker by value - the
                        // sender adopts it in place (no second flattening copy)
                        // and returns it intact so the sendmmsg/per-packet
                        // fallback below can still resend the unsent tail.
                        #[cfg(feature = "io_uring")]
                        if matches!(dispatch, OutboundDispatch::IoUringBatch) {
                            if let Some(worker) = self.uring_worker.as_ref() {
                                let reply = worker
                                    .send_batch_flat_with_disposition(
                                        socket_fd,
                                        std::mem::take(&mut batch_flat),
                                        std::mem::take(&mut batch_spans),
                                    )
                                    .await;
                                match reply.result {
                                    Ok(result) => {
                                        for (index, sent_slot) in batch_sent.iter_mut().enumerate()
                                        {
                                            *sent_slot = result.is_sent(index);
                                        }
                                        crate::telemetry::IO_URING_SUBMIT_PACKETS
                                            .inc_by(result.sent_count() as u64);
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                                    {
                                        log::debug!(
                                            "io_uring worker busy, falling back: {}",
                                            error
                                        );
                                        crate::telemetry::IO_URING_FALLBACKS.inc();
                                    }
                                    Err(error) => {
                                        return Err(self.transport_send_error(
                                            "client io_uring blocking worker",
                                            error,
                                        ));
                                    }
                                }
                                batch_flat = reply.flat;
                                batch_spans = reply.spans;
                            }
                        }

                        // sendmmsg receives only the slots not already accepted by
                        // io_uring. Its contiguous prefix is therefore relative to
                        // a retry subset, never to the original batch.
                        let mut fallback_indices: smallvec::SmallVec<[usize; 256]> =
                            smallvec::SmallVec::new();
                        let mut fallback_refs: smallvec::SmallVec<[&[u8]; 256]> =
                            smallvec::SmallVec::new();
                        for (index, &(start, len)) in batch_spans.iter().enumerate() {
                            if !batch_sent[index] {
                                fallback_indices.push(index);
                                fallback_refs.push(&batch_flat[start..start + len]);
                            }
                        }

                        // sendmmsg batch path (fallback from io_uring, or primary).
                        if fallback_refs.len() > 1 {
                            match try_sendmmsg_batch(
                                self.hotpath_adapter.as_ref(),
                                socket_fd,
                                OutboundDispatch::SendmmsgBatch,
                                &fallback_refs,
                            ) {
                                Ok(n) => {
                                    let sent_by_batch = n.min(fallback_indices.len());
                                    for index in fallback_indices.iter().take(sent_by_batch) {
                                        batch_sent[*index] = true;
                                    }
                                    crate::optimize::telemetry::IO_DRIVER_SENDMMSG_CALLS
                                        .fetch_add(1, Ordering::Relaxed);
                                    crate::optimize::telemetry::IO_DRIVER_SENDMMSG_PACKETS
                                        .fetch_add(sent_by_batch as u64, Ordering::Relaxed);
                                }
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::InvalidData
                                            | std::io::ErrorKind::WriteZero
                                    ) =>
                                {
                                    return Err(self.transport_send_error(
                                        "client UDP sendmmsg result",
                                        error,
                                    ));
                                }
                                Err(error) => {
                                    log::debug!("sendmmsg batch fallback: {}", error);
                                }
                            }
                        }
                    }

                    // Telemetry accumulates into locals across both passes and
                    // lands as one atomic batch instead of three RMWs per span.
                    let mut flush_bytes = 0u64;
                    let mut flush_packets = 0u64;
                    for (index, &(start, len)) in batch_spans.iter().enumerate() {
                        if batch_sent[index] {
                            continue;
                        }
                        let payload = &batch_flat[start..start + len];
                        if let Err(e) = socket.send(payload).await {
                            log::warn!("UDP send error: {}", e);
                            if flush_packets > 0 {
                                self.stats
                                    .udp_packets_sent
                                    .fetch_add(flush_packets, Ordering::Relaxed);
                                let global = crate::instrumentation::global();
                                global.transport.record_bytes_out(flush_bytes);
                                global.transport.record_packets_out(flush_packets);
                            }
                            return Err(self.transport_send_error("client TUN UDP send", e));
                        }
                        flush_bytes += payload.len() as u64;
                        flush_packets += 1;
                    }
                    for (index, &(_, len)) in batch_spans.iter().enumerate() {
                        if !batch_sent[index] {
                            continue;
                        }
                        flush_bytes += len as u64;
                        flush_packets += 1;
                    }
                    if flush_packets > 0 {
                        self.stats.udp_packets_sent.fetch_add(flush_packets, Ordering::Relaxed);
                        let global = crate::instrumentation::global();
                        global.transport.record_bytes_out(flush_bytes);
                        global.transport.record_packets_out(flush_packets);
                    }
                }
                Ok(_) => {
                    // No TUN data. Still flush pending transport packets (handshake/acks/pto)
                    // so short-lived and no-tun clients can complete connection setup.
                    if let Some(written) = self.poll_connection_send(&conn, &mut send_buf)? {
                        if written > 0 {
                            if let Err(e) = socket.send(&send_buf[..written]).await {
                                log::warn!("UDP send error (idle flush): {}", e);
                                return Err(self.transport_send_error("client idle UDP flush", e));
                            }
                            self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                            let global = crate::instrumentation::global();
                            global.transport.record_bytes_out(written as u64);
                            global.transport.record_packet_out();
                            continue;
                        }
                    }
                    self.wait_tun_idle(
                        &conn,
                        Duration::from_micros(self.config.poll_interval_us),
                        &tun_readable,
                    )
                    .await;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    // A nonblocking or interrupted read is a retryable idle state.
                    if let Some(written) = self.poll_connection_send(&conn, &mut send_buf)? {
                        if written > 0 {
                            if let Err(e) = socket.send(&send_buf[..written]).await {
                                log::warn!("UDP send error (error-path flush): {}", e);
                                return Err(
                                    self.transport_send_error("client read-error UDP flush", e)
                                );
                            } else {
                                self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                                let global = crate::instrumentation::global();
                                global.transport.record_bytes_out(written as u64);
                                global.transport.record_packet_out();
                                continue;
                            }
                        }
                    }
                    self.wait_tun_idle(&conn, Duration::from_millis(1), &tun_readable).await;
                }
                Err(error) => {
                    return Err(self.reader_stopped_error("client outbound TUN reader", error));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun, conn, socket, tunnel_stream_id);
            Err(EngineError::Transport(
                "outbound Linux TUN loop is only available on Linux".to_string(),
            ))
        }

        #[cfg(target_os = "linux")]
        Ok(())
    }

    /// Run the inbound loop (QUIC -> TUN).
    ///
    /// Receives packets from UDP, processes through FEC/Stealth, writes to TUN.
    /// On Linux with `io_uring` feature: uses a dedicated io_uring ring with
    /// pre-posted RecvMsg SQEs and an eventfd bridge to Tokio.
    pub async fn run_inbound(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: Arc<UdpSocket>,
        ingress: ClientTunnelIngress,
        handshake_event: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
    ) -> Result<(), EngineError> {
        // Try io_uring recv path on Linux.
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        {
            if let Some(uring) = Self::try_init_uring_recv(&socket, &conn) {
                return self
                    .run_inbound_uring(tun, conn, socket, ingress, handshake_event, uring)
                    .await;
            }
        }

        // Fallback: standard Tokio recv path.
        self.run_inbound_standard(tun, conn, socket, ingress, handshake_event).await
    }

    /// Standard inbound path using Tokio async recv + try_recv drain loop.
    async fn run_inbound_standard(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: Arc<UdpSocket>,
        ingress: ClientTunnelIngress,
        handshake_event: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
    ) -> Result<(), EngineError> {
        // One fixed-stride 64 KiB slot per recv, plus a span table recording
        // the per-datagram `(offset, len)` segments (GRO splits emit several
        // spans per slot). Payloads stay in place - no per-datagram copy.
        const RECV_SLOT: usize = 65535;
        let batch_cap = self.normalized_batch_size();
        let mut recv_flat = vec![0u8; batch_cap * RECV_SLOT];
        let mut send_buf = vec![0u8; 65535];
        let mut spans: Vec<(usize, usize)> = Vec::with_capacity(batch_cap * 4);
        let mut handshake_signaled = false;

        while !self.shutdown.load(Ordering::Relaxed) {
            let timeout = self.recv_timeout(&conn);
            let recv = tokio::time::timeout(
                timeout,
                Self::recv_wire_datagram(&socket, &mut recv_flat[..RECV_SLOT]),
            )
            .await;
            match recv {
                Err(_) => {}
                Ok(Err(e)) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        log::warn!("UDP recv error: {}", e);
                        return Err(self.transport_receive_error("client UDP receive", e));
                    }
                }
                Ok(Ok((len, gso))) if len > 0 => {
                    spans.clear();
                    let mut slots_used = 0usize;
                    Self::emit_wire_spans(0, len, gso, &mut spans);
                    slots_used += 1;

                    while spans.len() < batch_cap && slots_used < batch_cap {
                        let base = slots_used * RECV_SLOT;
                        match Self::try_recv_wire_datagram(
                            &socket,
                            &mut recv_flat[base..base + RECV_SLOT],
                        ) {
                            Ok((more, more_gso)) if more > 0 => {
                                Self::emit_wire_spans(base, more, more_gso, &mut spans);
                                slots_used += 1;
                            }
                            Ok(_) => break,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                log::debug!("UDP try_recv batch stop: {}", e);
                                return Err(
                                    self.transport_receive_error("client UDP batch receive", e)
                                );
                            }
                        }
                    }
                    if spans.len() > 1 {
                        crate::optimize::telemetry::IO_DRIVER_BATCH_DRAIN_PACKETS
                            .fetch_add((spans.len() - 1) as u64, Ordering::Relaxed);
                    }

                    self.process_inbound_batch(&conn, &tun, &ingress, &mut recv_flat, &spans)?;
                }
                Ok(Ok(_)) => {}
            }

            if !handshake_signaled {
                let established = { conn.lock().is_established() };
                if established {
                    let (lock, cvar) = &*handshake_event;
                    *lock.lock() = true;
                    cvar.notify_all();
                    handshake_signaled = true;
                }
            }

            // Flush any ACKs or PTO probes produced by recv or by a recovery
            // deadline that fired while we were waiting.
            self.flush_outbound(&conn, &socket, &mut send_buf).await?;
        }
        Ok(())
    }

    /// io_uring inbound path using pre-posted RecvMsg SQEs and eventfd bridge.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    async fn run_inbound_uring(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<ClientDataPlane>>,
        socket: Arc<UdpSocket>,
        ingress: ClientTunnelIngress,
        handshake_event: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
        uring: UringInboundRuntime,
    ) -> Result<(), EngineError> {
        let UringInboundRuntime { mut receiver, event } = uring;
        let mut send_buf = vec![0u8; 65535];
        let mut handshake_signaled = false;

        while !self.shutdown.load(Ordering::Relaxed) {
            // Wait for CQ notification via eventfd, capped by the connection's
            // earliest send deadline so recovery/PTO timers are not overslept.
            let timeout = self.recv_timeout(&conn);
            let readable = tokio::time::timeout(timeout, event.readable()).await;

            match readable {
                Ok(Ok(mut guard)) => {
                    // Clear the eventfd counter (read 8 bytes).
                    let mut efd_buf = [0u8; 8];
                    // SAFETY: `receiver.eventfd_fd()` returns the eventfd file descriptor
                    // created inside `UringRecvBatch::with_defaults`. It is valid and open
                    // for the lifetime of `receiver`. `efd_buf` is an 8-byte stack buffer
                    // (the exact width mandated by the eventfd ABI). We request exactly 8
                    // bytes, which is the only valid read size for an eventfd. The raw
                    // pointer cast to `*mut c_void` is safe for a `[u8; 8]` stack array.
                    let efd_ret = unsafe {
                        libc::read(
                            receiver.eventfd_fd(),
                            efd_buf.as_mut_ptr() as *mut libc::c_void,
                            8,
                        )
                    };
                    if efd_ret < 0 {
                        let error = std::io::Error::last_os_error();
                        if !matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) {
                            return Err(
                                self.transport_receive_error("client io_uring eventfd read", error)
                            );
                        }
                    } else if let Err(error) = validate_eventfd_read_len(efd_ret) {
                        return Err(self
                            .transport_receive_error("client io_uring eventfd short read", error));
                    }
                    guard.clear_ready();

                    // Drain all completed receives.
                    let completions = receiver.drain_completions().map_err(|e| {
                        self.transport_receive_error("client io_uring completion drain", e)
                    })?;

                    if !completions.is_empty() {
                        crate::telemetry::IO_URING_RECV_BATCHES.inc();
                        crate::telemetry::IO_URING_RECV_PACKETS.inc_by(completions.len() as u64);

                        // Telemetry accumulates into locals and lands as one
                        // atomic batch; early returns flush what was counted.
                        let flush_batch = |batch_bytes: u64, batch_packets: u64| {
                            if batch_packets > 0 {
                                self.stats
                                    .udp_packets_received
                                    .fetch_add(batch_packets, Ordering::Relaxed);
                                let global = crate::instrumentation::global();
                                global.transport.record_bytes_in(batch_bytes);
                                global.transport.record_packets_in(batch_packets);
                            }
                        };
                        let mut batch_bytes = 0u64;
                        let mut batch_packets = 0u64;
                        for mut c in completions {
                            batch_bytes += c.len() as u64;
                            batch_packets += 1;
                            {
                                let mut conn_guard = conn.lock();
                                let recv_result = if let Some(block) = c.block {
                                    conn_guard.recv_pooled_block(block, c.len)
                                } else {
                                    conn_guard.recv_mut(&mut c.data)
                                };
                                if let Err(e) = recv_result {
                                    log::debug!("Connection recv error: {:?}", e);
                                    flush_batch(batch_bytes, batch_packets);
                                    return Err(self.transport_receive_error(
                                        "client io_uring QUIC receive",
                                        e,
                                    ));
                                }
                            }

                            if let Err(error) = self
                                .poll_http3_to_ingress(&conn, &ingress)
                                .and_then(|()| self.drain_ingress_to_tun(&tun, &ingress))
                            {
                                flush_batch(batch_bytes, batch_packets);
                                return Err(error);
                            }
                        }
                        flush_batch(batch_bytes, batch_packets);
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("AsyncFd error on uring recv eventfd: {}", e);
                    return Err(self.transport_receive_error("client io_uring eventfd", e));
                }
                Err(_) => {
                    // Timeout - check shutdown, continue.
                }
            }

            if !handshake_signaled {
                let established = { conn.lock().is_established() };
                if established {
                    let (lock, cvar) = &*handshake_event;
                    *lock.lock() = true;
                    cvar.notify_all();
                    handshake_signaled = true;
                }
            }

            // Flush ACKs or PTO probes produced by the completions/timeout.
            self.flush_outbound(&conn, &socket, &mut send_buf).await?;
        }
        Ok(())
    }

    /// Try to initialise io_uring recv batch on the socket fd.
    #[cfg(all(target_os = "linux", feature = "io_uring"))]
    fn try_init_uring_recv(
        socket: &Arc<UdpSocket>,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
    ) -> Option<UringInboundRuntime> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        if crate::optimize::uring_batch::env_disabled() {
            return None;
        }

        let socket_fd = socket.as_raw_fd();

        // TODO-1007: multishot is the default client RX path. A single
        // RecvMulti SQE plus the provided-buffer ring removes the per-packet
        // re-arm entirely; measured on Omega (recv_flood_bench, kernel 6.17):
        // individual-datagram floods drain 4x fewer rounds at ~30% less CPU
        // than batch+GRO, and the buffer ring is 64x2KB pool blocks instead of
        // 64x64KB contiguous. batch+GRO only wins when receive coalescing can
        // actually engage - same-kernel paths (veth/loopback/virtio) where
        // skb->gso_size survives; wire traffic never arrives as GSO trains, so
        // WAN edge traffic is the multishot case. Set
        // QUICFUSCATE_IO_URING_RECV_MULTISHOT=0 to opt out (same-host/VM
        // deployments, or kernels where RecvMulti behaves badly). It must NOT
        // run with UDP_GRO enabled on the socket: IORING_OP_RECV carries no
        // msghdr, so a coalesced super-buffer would arrive without its
        // segment size and could not be split back into datagrams.
        let multishot_enabled = crate::env_utils::EnvSnapshot::capture()
            .flag("QUICFUSCATE_IO_URING_RECV_MULTISHOT", true);
        let mut receiver = if multishot_enabled {
            let memory_pool = { conn.lock().recv_memory_pool() };
            match crate::optimize::uring_batch::UringRecvMultishot::new_with_pool(
                socket_fd,
                64,
                2048,
                memory_pool,
            ) {
                Some(rx) => {
                    log::debug!("io_uring client recv: multishot provided-buffer ring");
                    Some(InboundReceiver::Multishot(rx))
                }
                None => None,
            }
        } else {
            None
        };

        if receiver.is_none() {
            // Prefer UDP_GRO when the kernel accepts it: one RecvMsg can then
            // deliver a coalesced super-buffer whose segment boundaries are
            // restored from the per-slot cmsg storage inside UringRecvBatch. GRO
            // needs 64 KiB buffers, which exceed pool block size, so this variant
            // uses contiguous buffers; the pool-backed path stays the fallback.
            let gro_enabled = qf_transport_udp::enable_udp_gro_fd(socket_fd).is_ok();
            let mut batch = if gro_enabled {
                crate::optimize::uring_batch::UringRecvBatch::with_defaults_gro(socket_fd, false)
            } else {
                None
            };
            if gro_enabled && batch.is_none() {
                // MTU-sized fallback slots cannot hold a super-buffer; a coalesced
                // arrival would set MSG_TRUNC and lose its tail.
                let _ = qf_transport_udp::disable_udp_gro_fd(socket_fd);
            } else if gro_enabled {
                log::debug!("io_uring client recv: UDP_GRO enabled (64 KiB slots)");
            }
            if batch.is_none() {
                let memory_pool = { conn.lock().recv_memory_pool() };
                batch = crate::optimize::uring_batch::UringRecvBatch::with_defaults_pool(
                    socket_fd,
                    false,
                    memory_pool,
                );
            }
            receiver = batch.map(InboundReceiver::Batch);
        }
        let mut receiver = receiver?;

        let post_result = match &mut receiver {
            InboundReceiver::Batch(rx) => rx.post_initial(),
            InboundReceiver::Multishot(rx) => rx.post_initial(),
        };
        if post_result.is_err() {
            log::debug!("io_uring recv post_initial failed");
            return None;
        }

        // dup() the eventfd so AsyncFd can take ownership of the copy
        // while UringRecvBatch retains the original (both sides close safely).
        // SAFETY: `receiver.eventfd_fd()` returns a valid open eventfd descriptor for
        // the lifetime of `receiver`. `dup()` creates a new independent fd referring to
        // the same underlying kernel object; the original is unaffected. We check for < 0
        // (error) before using `efd_dup`.
        let efd_dup = unsafe { libc::dup(receiver.eventfd_fd()) };
        if efd_dup < 0 {
            log::debug!("eventfd dup failed");
            return None;
        }
        // SAFETY: `efd_dup` is the freshly duplicated file descriptor obtained from the
        // successful `libc::dup()` call above. It is a valid, open fd that we have just
        // created, so we are taking its sole ownership here. `OwnedFd` will close it on
        // drop; the original eventfd in `receiver` is separately managed.
        let owned_efd = unsafe { OwnedFd::from_raw_fd(efd_dup) };
        let event = tokio::io::unix::AsyncFd::new(owned_efd).ok()?;

        log::info!("io_uring recv batch initialised (eventfd bridge active)");
        crate::telemetry::IO_URING_RECV_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);

        Some(UringInboundRuntime { receiver, event })
    }

    fn poll_http3_to_ingress(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        ingress: &ClientTunnelIngress,
    ) -> Result<(), EngineError> {
        let sink = ingress.clone();
        let result = conn.lock().poll_http3_with(|data| {
            if !sink.push(data) {
                log::debug!("client H3/MASQUE ingress queue rejected {} bytes", data.len());
            }
        });
        result.map_err(|error| self.transport_receive_error("client H3 poll", error))
    }

    fn drain_ingress_to_tun(
        &self,
        tun: &Arc<parking_lot::Mutex<TunInterface>>,
        ingress: &ClientTunnelIngress,
    ) -> Result<(), EngineError> {
        let mut drained = ingress.drain();
        if masque_trace_enabled() && !drained.is_empty() {
            log::info!("client ingress drain packets={}", drained.len());
        }
        for (index, packet) in drained.iter().enumerate() {
            let mut tun_guard = tun.lock();
            if let Err(error) = tun_guard.write_packet(packet) {
                // TODO-896: WouldBlock is transient kernel ring backpressure, not a
                // data-plane fault. Re-queue this packet and everything after it so
                // the next poll retries after the TUN fd becomes writable again.
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    self.stats.tun_write_backpressure.fetch_add(1, Ordering::Relaxed);
                    // `split_off` hands the unwritten suffix back without the
                    // `to_vec` copy; the already-written head buffers recycle.
                    let rest = drained.split_off(index);
                    ingress.recycle(drained);
                    ingress.restore(rest);
                    return Ok(());
                }
                log::warn!("TUN write error: {:?}", error);
                return Err(self.tun_write_error("client H3/MASQUE downlink", error));
            }
            self.stats.tun_packets_written.fetch_add(1, Ordering::Relaxed);
        }
        ingress.recycle(drained);
        Ok(())
    }

    /// Process a batch of received inbound packets through QUIC, H3/MASQUE, and TUN.
    fn process_inbound_batch(
        &self,
        conn: &Arc<parking_lot::Mutex<ClientDataPlane>>,
        tun: &Arc<parking_lot::Mutex<TunInterface>>,
        ingress: &ClientTunnelIngress,
        recv_flat: &mut [u8],
        spans: &[(usize, usize)],
    ) -> Result<(), EngineError> {
        // Telemetry accumulates into locals and lands as one atomic batch;
        // every early-return path flushes what was counted so the totals
        // match the former per-packet accounting exactly.
        let flush_batch = |batch_bytes: u64, batch_packets: u64| {
            if batch_packets > 0 {
                self.stats.udp_packets_received.fetch_add(batch_packets, Ordering::Relaxed);
                let global = crate::instrumentation::global();
                global.transport.record_bytes_in(batch_bytes);
                global.transport.record_packets_in(batch_packets);
            }
        };
        let mut batch_bytes = 0u64;
        let mut batch_packets = 0u64;
        for &(offset, len) in spans {
            let payload = &mut recv_flat[offset..offset + len];
            batch_bytes += len as u64;
            batch_packets += 1;

            {
                let mut conn_guard = conn.lock();
                if let Err(e) = conn_guard.recv_mut(payload) {
                    if masque_trace_enabled() {
                        log::info!("client conn.recv error bytes={} err={:?}", len, e);
                    } else {
                        log::debug!("Connection recv error: {:?}", e);
                    }
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    flush_batch(batch_bytes, batch_packets);
                    return Err(EngineError::DataPlane(DataPlaneFault::TransportReceive {
                        component: "client QUIC receive".to_string(),
                        error: e.to_string(),
                    }));
                }
                if masque_trace_enabled() {
                    log::info!("client conn.recv ok bytes={}", len);
                }
            }
            if let Err(error) = self
                .poll_http3_to_ingress(conn, ingress)
                .and_then(|()| self.drain_ingress_to_tun(tun, ingress))
            {
                flush_batch(batch_bytes, batch_packets);
                return Err(error);
            }
        }
        flush_batch(batch_bytes, batch_packets);
        Ok(())
    }
}

#[cfg(test)]
mod assignment_close_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn physical_close_is_sent_after_assignment_receive_before_teardown() {
        let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("client UDP"));
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("server UDP");
        let client_addr = client_socket.local_addr().expect("client address");
        let server_addr = server_socket.local_addr().expect("server address");
        client_socket.connect(server_addr).await.expect("connect client UDP");
        server_socket.connect(client_addr).await.expect("connect server UDP");

        let server_cid = b"assignment-server";
        let transport_config =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
                .expect("transport config");
        let client = crate::core::QuicFuscateConnection::new_client(
            "localhost",
            client_addr,
            server_addr,
            transport_config,
            crate::stealth::StealthConfig::default(),
            crate::fec::FecConfig::default(),
            crate::optimize::OptimizeConfig::default(),
            None,
            None,
            false,
        )
        .expect("Core client");
        let connection = Arc::new(parking_lot::Mutex::new(ClientDataPlane::single(client)));
        let barrier = Arc::new(tokio::sync::Notify::new());
        let mut driver = IoDriver::new(IoDriverConfig::default());
        driver.assignment_receive_barrier = Some(Arc::clone(&barrier));
        let assignment_connection = Arc::clone(&connection);
        let assignment_socket = Arc::clone(&client_socket);
        let task = tokio::spawn(async move {
            driver
                .negotiate_assignment(
                    &assignment_connection,
                    &assignment_socket,
                    1,
                    Instant::now() + Duration::from_secs(2),
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), barrier.notified())
            .await
            .expect("assignment reached UDP receive");
        let recv_info =
            crate::transport::RecvInfo { from: client_addr, to: server_addr, ecn: None };
        let mut packet = [0u8; 65_535];
        let first_length =
            tokio::time::timeout(Duration::from_secs(1), server_socket.recv(&mut packet))
                .await
                .expect("client Initial reaches server socket")
                .expect("receive client Initial");
        let (initial, _) = crate::transport::packet::parse_header(&packet[..first_length], 0)
            .expect("parse client Initial");
        let mut server_config =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
                .expect("server config");
        let mut peer = crate::transport::packet::accept(
            server_cid,
            Some(&initial.dcid),
            server_addr,
            client_addr,
            &mut server_config,
        )
        .expect("server transport");
        peer.set_destination_cid(crate::transport::ConnectionId::from_ref(&initial.scid));
        peer.enable_tls("unified").expect("install server Initial keys");
        peer.recv(&mut packet[..first_length], &recv_info).expect("open client Initial");
        while let Ok(Ok(length)) =
            tokio::time::timeout(Duration::from_millis(5), server_socket.recv(&mut packet)).await
        {
            let _ = peer.recv(&mut packet[..length], &recv_info);
        }

        assert_eq!(
            connection.lock().physical_mut().conn.process_crypto_frame(
                qf_transport_types::QuicEncryptionLevel::Initial,
                65_536,
                std::borrow::Cow::Borrowed(b"x"),
            ),
            Err(crate::error::ConnectionError::CryptoBufferExceeded)
        );
        server_socket.send(&[0xA5; 32]).await.expect("wake assignment receive");
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("assignment terminates")
            .expect("assignment task joins");
        assert!(result.is_err());
        assert!(matches!(
            connection.lock().physical().conn.local_error(),
            Some(crate::error::ConnectionError::CryptoBufferExceeded)
        ));

        let length = tokio::time::timeout(Duration::from_secs(1), server_socket.recv(&mut packet))
            .await
            .expect("terminal close reaches server socket")
            .expect("receive protected close");
        peer.recv(&mut packet[..length], &recv_info).expect("peer opens terminal close");
        assert!(matches!(
            peer.remote_error(),
            Some(crate::error::ConnectionError::PeerConnectionClosed { error_code: 0x0d, .. })
        ));
        assert!(tokio::time::timeout(Duration::from_millis(30), server_socket.recv(&mut packet))
            .await
            .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn physical_close_reports_unconnected_udp_socket_without_losing_cause() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("client UDP"));
        let local_addr = socket.local_addr().expect("client address");
        let peer_addr = "127.0.0.1:443".parse().expect("peer address");
        let config = crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
            .expect("transport config");
        let client = crate::core::QuicFuscateConnection::new_client(
            "localhost",
            local_addr,
            peer_addr,
            config,
            crate::stealth::StealthConfig::default(),
            crate::fec::FecConfig::default(),
            crate::optimize::OptimizeConfig::default(),
            None,
            None,
            false,
        )
        .expect("Core client");
        let connection = Arc::new(parking_lot::Mutex::new(ClientDataPlane::single(client)));
        assert_eq!(
            connection.lock().physical_mut().conn.process_crypto_frame(
                qf_transport_types::QuicEncryptionLevel::Initial,
                65_536,
                std::borrow::Cow::Borrowed(b"x"),
            ),
            Err(crate::error::ConnectionError::CryptoBufferExceeded)
        );

        let mut out = [0u8; 65_535];
        let result = IoDriver::new(IoDriverConfig::default())
            .flush_physical_close(&connection, &socket, &mut out)
            .await;
        assert!(matches!(
            result,
            Err(EngineError::DataPlane(DataPlaneFault::TransportSend { component, .. }))
                if component == "client assignment close UDP send"
        ));
        assert_eq!(
            connection.lock().physical().conn.local_error(),
            Some(&crate::error::ConnectionError::CryptoBufferExceeded)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn protected_inbound_crypto_failure_flushes_close_before_cached_cover() {
        let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("client UDP"));
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.expect("server UDP");
        let client_addr = client_socket.local_addr().expect("client address");
        let server_addr = server_socket.local_addr().expect("server address");
        client_socket.connect(server_addr).await.expect("connect client UDP");
        server_socket.connect(client_addr).await.expect("connect server UDP");

        let mut client_config =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
                .expect("client transport config");
        client_config.verify_peer = false;
        let client_stealth = crate::stealth::StealthConfig {
            reality_cover_targets: vec!["127.0.0.1:443".to_string()],
            ..crate::stealth::StealthConfig::default()
        };
        let mut client = crate::core::QuicFuscateConnection::new_client(
            "localhost",
            client_addr,
            server_addr,
            client_config,
            client_stealth,
            crate::fec::FecConfig::default(),
            crate::optimize::OptimizeConfig::default(),
            None,
            None,
            false,
        )
        .expect("Core client");
        let mut packet = [0u8; 65_535];
        let initial_length = client.send(&mut packet).expect("client Initial");
        let (initial, _) = crate::transport::packet::parse_header(&packet[..initial_length], 0)
            .expect("parse client Initial");
        let server_cid = crate::transport::ConnectionId::from_ref(b"assignment-server");
        let initial_dcid = crate::transport::ConnectionId::from_ref(&initial.dcid);
        let mut server_config =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
                .expect("server transport config");
        server_config.verify_peer = false;
        let mut server = crate::core::QuicFuscateConnection::new_server(
            &server_cid,
            Some(&initial_dcid),
            server_addr,
            client_addr,
            &mut server_config,
            crate::stealth::StealthConfig::default(),
            crate::fec::FecConfig::default(),
            crate::optimize::OptimizeConfig::default(),
        )
        .expect("Core server");
        server.conn.set_destination_cid(crate::transport::ConnectionId::from_ref(&initial.scid));
        let client_to_server =
            crate::transport::RecvInfo { from: client_addr, to: server_addr, ecn: None };
        let server_to_client =
            crate::transport::RecvInfo { from: server_addr, to: client_addr, ecn: None };
        server
            .conn
            .recv(&mut packet[..initial_length], &client_to_server)
            .expect("open client Initial");
        for _ in 0..64 {
            let mut progressed = false;
            match client.conn.send(&mut packet) {
                Ok((length, _)) => {
                    server
                        .conn
                        .recv(&mut packet[..length], &client_to_server)
                        .expect("deliver client TLS flight");
                    progressed = true;
                }
                Err(crate::error::ConnectionError::Done) => {}
                Err(error) => panic!("client TLS send failed: {error}"),
            }
            match server.conn.send(&mut packet) {
                Ok((length, _)) => {
                    client
                        .conn
                        .recv(&mut packet[..length], &server_to_client)
                        .expect("deliver server TLS flight");
                    progressed = true;
                }
                Err(crate::error::ConnectionError::Done) => {}
                Err(error) => panic!("server TLS send failed: {error}"),
            }
            if client.conn.tls_handshake_complete() && server.conn.tls_handshake_complete() {
                break;
            }
            if !progressed {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        assert!(client.conn.tls_handshake_complete());
        assert!(server.conn.tls_handshake_complete());

        let connection = Arc::new(parking_lot::Mutex::new(ClientDataPlane::single(client)));
        let barrier = Arc::new(tokio::sync::Notify::new());
        let mut driver = IoDriver::new(IoDriverConfig::default());
        driver.assignment_receive_barrier = Some(Arc::clone(&barrier));
        let assignment_connection = Arc::clone(&connection);
        let assignment_socket = Arc::clone(&client_socket);
        let task = tokio::spawn(async move {
            driver
                .negotiate_assignment(
                    &assignment_connection,
                    &assignment_socket,
                    1,
                    Instant::now() + Duration::from_secs(2),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), barrier.notified())
            .await
            .expect("assignment reached UDP receive");
        let mut drained_before_error = 0;
        for _ in 0..32 {
            let Ok(Ok(length)) =
                tokio::time::timeout(Duration::from_millis(5), server_socket.recv(&mut packet))
                    .await
            else {
                break;
            };
            server.recv_mut(&mut packet[..length]).expect("consume pre-error assignment output");
            drained_before_error += 1;
        }
        assert!(
            !task.is_finished(),
            "assignment ended before fault injection after draining {drained_before_error} packets"
        );

        let manager = connection.lock().physical().stealth_manager();
        manager
            .reality_proxy
            .as_ref()
            .expect("configured Reality proxy")
            .send_cached_response(server_addr, b"queued cover response".to_vec());
        let frame = crate::transport::Frame::Crypto {
            offset: 65_536,
            data: std::borrow::Cow::Borrowed(b"x"),
        };
        let length = server
            .conn
            .send_test_short_frame(&mut packet, &frame)
            .expect("seal protected out-of-window CRYPTO frame");
        server_socket.send(&packet[..length]).await.expect("send protected CRYPTO frame");
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("assignment terminates")
            .expect("assignment task joins");
        assert!(result.is_err());
        let (local_error, closed) = {
            let guard = connection.lock();
            (guard.physical().conn.local_error().cloned(), guard.physical().conn.is_closed())
        };
        assert_eq!(
            local_error,
            Some(crate::error::ConnectionError::CryptoBufferExceeded),
            "assignment={result:?}, closed={closed}, fallback_invocations={}",
            manager.fallback_invocations_for_test()
        );
        assert_eq!(manager.fallback_invocations_for_test(), 0);

        let close_length =
            tokio::time::timeout(Duration::from_secs(1), server_socket.recv(&mut packet))
                .await
                .expect("close reaches peer UDP socket")
                .expect("receive protected close");
        let recv_info =
            crate::transport::RecvInfo { from: client_addr, to: server_addr, ecn: None };
        server
            .conn
            .recv(&mut packet[..close_length], &recv_info)
            .expect("server decrypts terminal close");
        assert!(matches!(
            server.conn.remote_error(),
            Some(crate::error::ConnectionError::PeerConnectionClosed { error_code: 0x0d, .. })
        ));
        assert_eq!(manager.poll_fallback().expect("cover retained").data, b"queued cover response");
        assert!(tokio::time::timeout(Duration::from_millis(30), server_socket.recv(&mut packet))
            .await
            .is_err());
    }
}
