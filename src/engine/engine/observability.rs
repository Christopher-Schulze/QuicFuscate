use super::{
    DisconnectReason, EngineError, EngineEvent, EngineState, QuicFuscateEngine, StatsSnapshot,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

impl QuicFuscateEngine {
    // ========================================================================
    // Internal helpers
    // ========================================================================

    pub(super) fn refresh_stats(&self) {
        let metrics = &self.instrumentation;
        if let Some(metrics) = self.server_metrics.as_ref() {
            self.stats
                .bytes_sent
                .store(metrics.bytes_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .bytes_received
                .store(metrics.bytes_in.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_sent
                .store(metrics.packets_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_received
                .store(metrics.packets_in.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .active_streams
                .store(metrics.clients_active.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats.rtt_ms.store(0, Ordering::Relaxed);
            self.stats.loss_percent.store(0, Ordering::Relaxed);
            self.stats
                .data_plane_ready
                .store(metrics.tun_data_plane_ready.load(Ordering::Acquire), Ordering::Relaxed);
            self.stats
                .data_plane_faults
                .store(metrics.tun_data_plane_faults.load(Ordering::Relaxed), Ordering::Relaxed);
        } else {
            self.stats
                .bytes_sent
                .store(metrics.transport.bytes_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .bytes_received
                .store(metrics.transport.bytes_in.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_sent
                .store(metrics.transport.packets_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_received
                .store(metrics.transport.packets_in.load(Ordering::Relaxed), Ordering::Relaxed);
            let active_streams = self
                .client_runtime
                .as_ref()
                .and_then(|runtime| runtime.connection())
                .map(|conn| u64::from(conn.is_established()))
                .unwrap_or(0);
            self.stats.active_streams.store(active_streams, Ordering::Relaxed);
            self.stats
                .rtt_ms
                .store(metrics.transport.avg_rtt_ms().round() as u64, Ordering::Relaxed);
            self.stats
                .loss_percent
                .store(metrics.transport.loss_rate().round() as u64, Ordering::Relaxed);
            if let Some(runtime) = self.client_runtime.as_ref() {
                self.stats
                    .data_plane_ready
                    .store(u64::from(runtime.data_plane_available()), Ordering::Relaxed);
                self.stats.data_plane_faults.store(
                    runtime.io_driver_stats().map(|stats| stats.data_plane_faults).unwrap_or(0),
                    Ordering::Relaxed,
                );
            } else {
                self.stats.data_plane_ready.store(0, Ordering::Relaxed);
                self.stats.data_plane_faults.store(0, Ordering::Relaxed);
            }
        }
        if let Some(start) = self.start_time {
            self.stats
                .uptime_secs
                .store(self.clock.elapsed_since(start).as_secs(), Ordering::Relaxed);
        }
        self.stats.stealth_mode.store(self.config.stealth.mode as u64, Ordering::Relaxed);
        let effective_fec = self.active_fec_mode().unwrap_or(self.config.fec.mode);
        self.stats.fec_mode.store(effective_fec as u64, Ordering::Relaxed);
    }

    pub(super) fn set_state(&mut self, state: EngineState) {
        self.state = state;
    }

    pub(super) fn fail_start(&mut self, old_state: EngineState, error: EngineError) -> EngineError {
        self.set_state(EngineState::Error);
        self.notify_state_change(old_state, EngineState::Error);
        error
    }

    pub(super) fn notify_state_change(&self, old: EngineState, new: EngineState) {
        self.emit_event(EngineEvent::StateChanged { old, new });
        for cb in self.callbacks.lock().clone() {
            cb.on_state_change(old, new);
        }
    }

    pub(super) fn notify_connected(&self, remote: SocketAddr) {
        self.emit_event(EngineEvent::Connected { remote });
        for cb in self.callbacks.lock().clone() {
            cb.on_connected(remote);
        }
    }

    pub(super) fn notify_disconnected(&self, reason: DisconnectReason) {
        self.emit_event(EngineEvent::Disconnected { reason: reason.clone() });
        for cb in self.callbacks.lock().clone() {
            cb.on_disconnected(reason.clone());
        }
    }

    pub(super) fn notify_stats_update(&self, stats: &StatsSnapshot) {
        self.emit_event(EngineEvent::StatsUpdated { stats: stats.clone() });
        for cb in self.callbacks.lock().clone() {
            cb.on_stats_update(stats);
        }
    }

    pub(super) fn notify_stealth_escalation(&self, from: u8, to: u8) {
        self.emit_event(EngineEvent::StealthEscalated { from, to });
        for cb in self.callbacks.lock().clone() {
            cb.on_stealth_escalation(from, to);
        }
    }

    pub(super) fn notify_error(&self, error: &EngineError) {
        self.emit_event(EngineEvent::Error { error: error.clone() });
        for cb in self.callbacks.lock().clone() {
            cb.on_error(error);
        }
    }

    pub(super) fn emit_event(&self, event: EngineEvent) {
        let mut sinks = self.event_sinks.lock();
        sinks.retain(|tx| tx.send(event.clone()).is_ok());
    }
}
