use super::*;

impl QuicFuscateConnection {
    pub(super) fn inject_qkey_auth_header(
        token: Option<&str>,
        headers: &mut Vec<crate::transport::h3::Header>,
    ) {
        let Some(token) = token else {
            return;
        };
        let token = token.trim();
        if token.is_empty() {
            return;
        }
        headers.retain(|h| h.name() != b"x-qf-auth");
        headers.push(crate::transport::h3::Header::new(b"x-qf-auth", token.as_bytes()));
    }

    pub(super) fn inject_connection_generation_header(
        generation: Option<u64>,
        headers: &mut Vec<crate::transport::h3::Header>,
    ) {
        let Some(generation) = generation.filter(|generation| *generation != 0) else {
            return;
        };
        let value = generation.to_string();
        headers.retain(|header| !header.name().eq_ignore_ascii_case(b"x-qf-generation"));
        headers.push(crate::transport::h3::Header::new(b"x-qf-generation", value.as_bytes()));
    }

    pub(super) fn inject_circuit_headers(
        circuit_id: Option<[u8; 16]>,
        hop_budget: Option<u8>,
        headers: &mut Vec<crate::transport::h3::Header>,
    ) {
        let (Some(circuit_id), Some(hop_budget)) = (circuit_id, hop_budget) else {
            return;
        };
        let circuit_id = circuit_id.iter().fold(String::with_capacity(32), |mut value, byte| {
            use std::fmt::Write as _;
            let _ = write!(value, "{byte:02x}");
            value
        });
        let hop_budget = hop_budget.to_string();
        headers.retain(|header| {
            !header.name().eq_ignore_ascii_case(b"x-qf-circuit-id")
                && !header.name().eq_ignore_ascii_case(b"x-qf-hop-budget")
        });
        headers.push(crate::transport::h3::Header::new(b"x-qf-circuit-id", circuit_id.as_bytes()));
        headers.push(crate::transport::h3::Header::new(b"x-qf-hop-budget", hop_budget.as_bytes()));
    }

    pub(super) fn build_masque_request_headers(&self) -> Vec<crate::transport::h3::Header> {
        let mut headers = Vec::new();
        Self::inject_qkey_auth_header(self.qkey_auth_token_hex.as_deref(), &mut headers);
        Self::inject_connection_generation_header(self.client_connection_generation, &mut headers);
        Self::inject_circuit_headers(self.circuit_id, self.circuit_hop_budget, &mut headers);
        headers
    }
}
