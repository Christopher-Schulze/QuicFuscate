//! Compatibility projection for the transport NAT traversal leaf crate.

pub use qf_transport_nat::config::{NatDiscoveryReason, NatTraversalConfig, NatTraversalMode};
pub use qf_transport_nat::nat::{
    CandidateType, IceAgent, IceCandidate, NatError, NatPathDiscovery, StunClient, TurnClient,
};
