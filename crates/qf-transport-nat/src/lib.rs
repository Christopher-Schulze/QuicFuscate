//! NAT traversal contracts and STUN/TURN/ICE runtime helpers.
//!
//! The root package keeps compatibility projections for the established
//! `quicfuscate::transport::nat` and transport configuration paths.

pub mod config;
pub mod nat;

pub use config::{NatDiscoveryReason, NatTraversalConfig, NatTraversalMode, NatTraversalSection};
pub use nat::{
    CandidateType, IceAgent, IceCandidate, NatError, NatPathDiscovery, StunClient, TurnClient,
};
