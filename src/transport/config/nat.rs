use super::{Config, NatTraversalConfig, NatTraversalMode};

impl Config {
    // --- NAT traversal (TODO-454) ---

    /// Sets the NAT traversal configuration (STUN/TURN/ICE). Replaces any
    /// previously configured NAT traversal settings.
    pub fn set_nat_traversal(&mut self, config: NatTraversalConfig) {
        self.nat_traversal = config.normalized();
    }

    /// Returns a reference to the current NAT traversal configuration.
    pub fn nat_traversal(&self) -> &NatTraversalConfig {
        &self.nat_traversal
    }

    /// Enables or disables NAT traversal as a whole.
    pub fn enable_nat_traversal(&mut self, enabled: bool) {
        self.nat_traversal.enabled = enabled;
        if !enabled {
            self.nat_traversal.mode = NatTraversalMode::Off;
        } else if self.nat_traversal.mode == NatTraversalMode::Off {
            self.nat_traversal.mode = NatTraversalMode::ConnectivityFallback;
        }
    }

    /// Sets the NAT traversal discovery policy.
    pub fn set_nat_traversal_mode(&mut self, mode: NatTraversalMode) {
        self.nat_traversal.mode = mode;
        self.nat_traversal.enabled = mode != NatTraversalMode::Off;
    }

    /// Sets the list of STUN servers used for server-reflexive candidate
    /// discovery.
    pub fn set_stun_servers(&mut self, servers: Vec<std::net::SocketAddr>) {
        self.nat_traversal.stun_servers = servers;
    }

    /// Sets the list of TURN servers used for relayed candidates.
    pub fn set_turn_servers(&mut self, servers: Vec<std::net::SocketAddr>) {
        self.nat_traversal.turn_servers = servers;
    }

    /// Enables or disables ICE candidate gathering and pair selection.
    pub fn enable_ice(&mut self, enabled: bool) {
        self.nat_traversal.ice_enabled = enabled;
    }

    /// Sets the minimum interval between NAT discovery probe bursts.
    pub fn set_nat_probe_interval_ms(&mut self, interval_ms: u64) {
        self.nat_traversal.probe_interval_ms = interval_ms.max(1_000);
    }

    /// Sets the maximum number of candidates returned by one discovery run.
    pub fn set_nat_max_candidates(&mut self, max_candidates: usize) {
        self.nat_traversal.max_candidates = max_candidates.max(1);
    }

    /// Returns true if NAT traversal is enabled.
    pub fn nat_traversal_enabled(&self) -> bool {
        self.nat_traversal.enabled
    }

    /// Returns true if ICE is enabled.
    pub fn ice_enabled(&self) -> bool {
        self.nat_traversal.ice_enabled
    }
}
