//! Authenticated application control messages carried by the canonical MASQUE flow.
//!
//! The assignment capsule is deliberately independent from raw tunnel packets. It is
//! versioned, bounded, and validated before any platform TUN state is changed.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Private MASQUE capsule type used for server-assigned client interface state.
pub const CLIENT_ASSIGNMENT_CAPSULE_TYPE: u64 = 0x40;
/// Current wire version of the client assignment payload.
pub const CLIENT_ASSIGNMENT_VERSION: u8 = 1;
/// Hard upper bound for one assignment capsule payload.
pub const MAX_CLIENT_ASSIGNMENT_PAYLOAD: usize = 256;
/// Maximum number of DNS servers carried by one assignment.
pub const MAX_CLIENT_ASSIGNMENT_DNS_SERVERS: usize = 4;
/// RFC 9484 ADDRESS_ASSIGN capsule type.
pub const CONNECT_IP_ADDRESS_ASSIGN_CAPSULE_TYPE: u64 = 0x01;
/// RFC 9484 ROUTE_ADVERTISEMENT capsule type.
pub const CONNECT_IP_ROUTE_ADVERTISEMENT_CAPSULE_TYPE: u64 = 0x03;

const FLAG_ENABLED: u8 = 0x01;
const FLAG_IPV4: u8 = 0x02;
const FLAG_IPV6: u8 = 0x04;
const FLAG_DNS: u8 = 0x08;
const KNOWN_FLAGS: u8 = FLAG_ENABLED | FLAG_IPV4 | FLAG_IPV6 | FLAG_DNS;

/// Whether the server permits the client tunnel interface to be activated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentMode {
    /// The assignment contains at least one usable address family.
    Enabled,
    /// The server explicitly disables client interface activation.
    Disabled,
}

/// Explicit order of address families in the assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressFamilyOrder {
    /// No address family is present.
    None = 0,
    /// IPv4 is serialized before IPv6.
    Ipv4ThenIpv6 = 1,
    /// IPv6 is serialized before IPv4.
    Ipv6ThenIpv4 = 2,
    /// Only IPv4 is present.
    Ipv4Only = 3,
    /// Only IPv6 is present.
    Ipv6Only = 4,
}

impl AddressFamilyOrder {
    fn decode(value: u8) -> Result<Self, AssignmentError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Ipv4ThenIpv6),
            2 => Ok(Self::Ipv6ThenIpv4),
            3 => Ok(Self::Ipv4Only),
            4 => Ok(Self::Ipv6Only),
            other => Err(AssignmentError::InvalidFamilyOrder(other)),
        }
    }
}

/// One assigned IPv4 address and its contiguous prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignedIpv4 {
    /// Client-side IPv4 address.
    pub address: Ipv4Addr,
    /// IPv4 prefix length.
    pub prefix: u8,
}

/// One assigned IPv6 address and its prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignedIpv6 {
    /// Client-side IPv6 address.
    pub address: Ipv6Addr,
    /// IPv6 prefix length.
    pub prefix: u8,
}

/// Complete server assignment for one authenticated client connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAssignment {
    /// Server session identity bound to the authenticated QUIC connection.
    pub session_id: u64,
    /// Client-selected connection generation echoed by the server.
    pub generation: u64,
    /// Whether TUN activation is permitted.
    pub mode: AssignmentMode,
    /// Explicit address-family ordering contract.
    pub family_order: AddressFamilyOrder,
    /// Optional assigned IPv4 address.
    pub ipv4: Option<AssignedIpv4>,
    /// Optional assigned IPv6 address.
    pub ipv6: Option<AssignedIpv6>,
    /// DNS servers supplied by the authenticated server session.
    pub dns_servers: Vec<IpAddr>,
    /// Assigned TUN MTU. Zero is reserved for disabled assignments.
    pub mtu: u16,
}

impl ClientAssignment {
    /// Build and validate an enabled assignment.
    pub fn enabled(
        session_id: u64,
        generation: u64,
        ipv4: Option<AssignedIpv4>,
        ipv6: Option<AssignedIpv6>,
        mtu: u16,
        dns_servers: Vec<IpAddr>,
    ) -> Result<Self, AssignmentError> {
        let family_order = family_order_for(ipv4.is_some(), ipv6.is_some(), false);
        let assignment = Self {
            session_id,
            generation,
            mode: AssignmentMode::Enabled,
            family_order,
            ipv4,
            ipv6,
            dns_servers,
            mtu,
        };
        assignment.validate()?;
        Ok(assignment)
    }

    /// Build and validate an explicit disabled assignment.
    pub fn disabled(session_id: u64, generation: u64) -> Result<Self, AssignmentError> {
        let assignment = Self {
            session_id,
            generation,
            mode: AssignmentMode::Disabled,
            family_order: AddressFamilyOrder::None,
            ipv4: None,
            ipv6: None,
            dns_servers: Vec::new(),
            mtu: 0,
        };
        assignment.validate()?;
        Ok(assignment)
    }

    /// Validate all semantic bounds and cross-field invariants.
    pub fn validate(&self) -> Result<(), AssignmentError> {
        self.validate_mode_and_addresses()?;
        self.validate_dns()?;
        if self.session_id == 0 {
            return Err(AssignmentError::InvalidIdentity("session_id"));
        }
        if self.generation == 0 {
            return Err(AssignmentError::InvalidIdentity("generation"));
        }
        Ok(())
    }

    fn validate_mode_and_addresses(&self) -> Result<(), AssignmentError> {
        match self.mode {
            AssignmentMode::Disabled => {
                if self.family_order != AddressFamilyOrder::None
                    || self.ipv4.is_some()
                    || self.ipv6.is_some()
                    || !self.dns_servers.is_empty()
                    || self.mtu != 0
                {
                    return Err(AssignmentError::DisabledPayloadNotEmpty);
                }
            }
            AssignmentMode::Enabled => {
                if self.ipv4.is_none() && self.ipv6.is_none() {
                    return Err(AssignmentError::NoAddressFamily);
                }
                if self.mtu < 576 {
                    return Err(AssignmentError::InvalidMtu(self.mtu));
                }
                if self.ipv6.is_some() && self.mtu < 1280 {
                    return Err(AssignmentError::Ipv6MtuTooSmall(self.mtu));
                }
                let expected = family_order_for(
                    self.ipv4.is_some(),
                    self.ipv6.is_some(),
                    self.family_order == AddressFamilyOrder::Ipv6ThenIpv4,
                );
                if self.family_order != expected {
                    return Err(AssignmentError::FamilyOrderMismatch {
                        expected,
                        actual: self.family_order,
                    });
                }
                if let Some(ipv4) = self.ipv4 {
                    if ipv4.prefix > 32 {
                        return Err(AssignmentError::InvalidIpv4Prefix(ipv4.prefix));
                    }
                }
                if let Some(ipv6) = self.ipv6 {
                    if ipv6.prefix > 128 {
                        return Err(AssignmentError::InvalidIpv6Prefix(ipv6.prefix));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_dns(&self) -> Result<(), AssignmentError> {
        if self.dns_servers.len() > MAX_CLIENT_ASSIGNMENT_DNS_SERVERS {
            return Err(AssignmentError::TooManyDnsServers(self.dns_servers.len()));
        }
        let mut unique = HashSet::with_capacity(self.dns_servers.len());
        for server in &self.dns_servers {
            if !unique.insert(*server) {
                return Err(AssignmentError::DuplicateDnsServer(*server));
            }
        }
        Ok(())
    }

    /// Encode this assignment into the bounded capsule payload format.
    pub fn encode(&self) -> Result<Vec<u8>, AssignmentError> {
        self.validate()?;
        let mut out = Vec::with_capacity(MAX_CLIENT_ASSIGNMENT_PAYLOAD.min(128));
        out.push(CLIENT_ASSIGNMENT_VERSION);
        out.push(self.flags());
        out.push(self.family_order as u8);
        out.push(0);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.mtu.to_be_bytes());
        self.encode_addresses(&mut out);
        out.push(self.dns_servers.len() as u8);
        for server in &self.dns_servers {
            encode_ip(&mut out, *server);
        }
        if out.len() > MAX_CLIENT_ASSIGNMENT_PAYLOAD {
            return Err(AssignmentError::PayloadTooLarge(out.len()));
        }
        Ok(out)
    }

    /// Encode the RFC 9484 address and full-tunnel route capsules that precede
    /// the private operational assignment capsule.
    pub fn encode_connect_ip_capsules(&self) -> Result<Vec<(u64, Vec<u8>)>, AssignmentError> {
        self.validate()?;
        if self.mode == AssignmentMode::Disabled {
            return Ok(Vec::new());
        }
        let mut addresses = Vec::with_capacity(32);
        if let Some(ipv4) = self.ipv4 {
            encode_quic_varint(0, &mut addresses);
            addresses.push(4);
            addresses.extend_from_slice(&ipv4.address.octets());
            addresses.push(32);
        }
        if let Some(ipv6) = self.ipv6 {
            encode_quic_varint(0, &mut addresses);
            addresses.push(6);
            addresses.extend_from_slice(&ipv6.address.octets());
            addresses.push(128);
        }

        let mut routes = Vec::with_capacity(44);
        if self.ipv4.is_some() {
            routes.push(4);
            routes.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            routes.extend_from_slice(&Ipv4Addr::BROADCAST.octets());
            routes.push(0);
        }
        if self.ipv6.is_some() {
            routes.push(6);
            routes.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
            routes.extend_from_slice(&Ipv6Addr::from(u128::MAX).octets());
            routes.push(0);
        }
        Ok(vec![
            (CONNECT_IP_ADDRESS_ASSIGN_CAPSULE_TYPE, addresses),
            (CONNECT_IP_ROUTE_ADVERTISEMENT_CAPSULE_TYPE, routes),
        ])
    }

    fn flags(&self) -> u8 {
        let mut flags = if self.mode == AssignmentMode::Enabled { FLAG_ENABLED } else { 0 };
        if self.ipv4.is_some() {
            flags |= FLAG_IPV4;
        }
        if self.ipv6.is_some() {
            flags |= FLAG_IPV6;
        }
        if !self.dns_servers.is_empty() {
            flags |= FLAG_DNS;
        }
        flags
    }

    fn encode_addresses(&self, out: &mut Vec<u8>) {
        if let Some(ipv4) = self.ipv4 {
            out.push(ipv4.prefix);
            out.extend_from_slice(&ipv4.address.octets());
        }
        if let Some(ipv6) = self.ipv6 {
            out.push(ipv6.prefix);
            out.extend_from_slice(&ipv6.address.octets());
        }
    }

    /// Decode and validate one assignment capsule payload.
    pub fn decode(payload: &[u8]) -> Result<Self, AssignmentError> {
        if payload.len() > MAX_CLIENT_ASSIGNMENT_PAYLOAD {
            return Err(AssignmentError::PayloadTooLarge(payload.len()));
        }
        let mut reader = Reader::new(payload);
        let version = reader.u8()?;
        if version != CLIENT_ASSIGNMENT_VERSION {
            return Err(AssignmentError::UnsupportedVersion(version));
        }
        let flags = reader.u8()?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(AssignmentError::InvalidFlags(flags));
        }
        let family_order = AddressFamilyOrder::decode(reader.u8()?)?;
        if reader.u8()? != 0 {
            return Err(AssignmentError::NonZeroReservedField);
        }
        let session_id = reader.u64()?;
        let generation = reader.u64()?;
        let mtu = reader.u16()?;
        let ipv4 = if flags & FLAG_IPV4 != 0 {
            Some(AssignedIpv4 { prefix: reader.u8()?, address: reader.ipv4()? })
        } else {
            None
        };
        let ipv6 = if flags & FLAG_IPV6 != 0 {
            Some(AssignedIpv6 { prefix: reader.u8()?, address: reader.ipv6()? })
        } else {
            None
        };
        let dns_count = usize::from(reader.u8()?);
        if dns_count > MAX_CLIENT_ASSIGNMENT_DNS_SERVERS {
            return Err(AssignmentError::TooManyDnsServers(dns_count));
        }
        let mut dns_servers = Vec::with_capacity(dns_count);
        for _ in 0..dns_count {
            dns_servers.push(reader.ip()?);
        }
        reader.finish()?;
        if (flags & FLAG_DNS != 0) != (dns_count > 0) {
            return Err(AssignmentError::DnsFlagMismatch);
        }
        let mode = if flags & FLAG_ENABLED != 0 {
            AssignmentMode::Enabled
        } else {
            AssignmentMode::Disabled
        };
        let assignment =
            Self { session_id, generation, mode, family_order, ipv4, ipv6, dns_servers, mtu };
        assignment.validate()?;
        Ok(assignment)
    }
}

fn encode_quic_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
        }
        _ => output
            .extend_from_slice(&(value.min((1 << 62) - 1) | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

fn family_order_for(has_ipv4: bool, has_ipv6: bool, ipv6_first: bool) -> AddressFamilyOrder {
    match (has_ipv4, has_ipv6, ipv6_first) {
        (false, false, _) => AddressFamilyOrder::None,
        (true, false, _) => AddressFamilyOrder::Ipv4Only,
        (false, true, _) => AddressFamilyOrder::Ipv6Only,
        (true, true, true) => AddressFamilyOrder::Ipv6ThenIpv4,
        (true, true, false) => AddressFamilyOrder::Ipv4ThenIpv6,
    }
}

fn encode_ip(out: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(ipv4) => {
            out.push(4);
            out.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            out.push(6);
            out.extend_from_slice(&ipv6.octets());
        }
    }
}

/// Result of feeding a control capsule to the assignment receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentReceipt {
    /// A first valid assignment was accepted.
    Accepted,
    /// The exact same assignment was received again and is harmless.
    Duplicate,
    /// A different control capsule was ignored by this assignment receiver.
    Ignored,
}

/// Client-side state machine for one connection generation.
#[derive(Debug)]
pub struct AssignmentReceiver {
    expected_generation: u64,
    assignment: Option<ClientAssignment>,
}

impl AssignmentReceiver {
    /// Create a receiver bound to one nonzero client connection generation.
    pub fn new(expected_generation: u64) -> Result<Self, AssignmentError> {
        if expected_generation == 0 {
            return Err(AssignmentError::InvalidIdentity("generation"));
        }
        Ok(Self { expected_generation, assignment: None })
    }

    /// Decode and accept one control capsule with duplicate/conflict handling.
    pub fn receive(
        &mut self,
        capsule_type: u64,
        payload: &[u8],
    ) -> Result<AssignmentReceipt, AssignmentError> {
        if capsule_type != CLIENT_ASSIGNMENT_CAPSULE_TYPE {
            return Ok(AssignmentReceipt::Ignored);
        }
        let assignment = ClientAssignment::decode(payload)?;
        if assignment.generation != self.expected_generation {
            return Err(AssignmentError::UnexpectedGeneration {
                expected: self.expected_generation,
                actual: assignment.generation,
            });
        }
        match self.assignment.as_ref() {
            None => {
                self.assignment = Some(assignment);
                Ok(AssignmentReceipt::Accepted)
            }
            Some(previous) if previous == &assignment => Ok(AssignmentReceipt::Duplicate),
            Some(_) => Err(AssignmentError::ConflictingAssignment),
        }
    }

    /// Return the accepted assignment, if any.
    pub fn assignment(&self) -> Option<&ClientAssignment> {
        self.assignment.as_ref()
    }
}

/// Bounded callback state shared by a client control-plane poller.
///
/// The first malformed, stale, or conflicting assignment is retained as a
/// terminal failure. This keeps generic and standalone clients on the same
/// receiver semantics instead of maintaining separate callback parsers.
#[derive(Debug)]
pub struct AssignmentReception {
    receiver: AssignmentReceiver,
    failure: Option<AssignmentError>,
    connect_ip_addresses: Option<Vec<(IpAddr, u8)>>,
    connect_ip_routes: Option<Vec<(IpAddr, IpAddr, u8)>>,
    connect_ip_required: bool,
    connect_ip_ready: bool,
}

impl AssignmentReception {
    /// Create a reception state bound to one reconnect generation.
    pub fn new(expected_generation: u64) -> Result<Self, AssignmentError> {
        Self::with_connect_ip_requirement(expected_generation, false)
    }

    /// Create reception state that withholds the private assignment until the
    /// matching RFC 9484 address and route capsules have both arrived.
    pub fn new_connect_ip(expected_generation: u64) -> Result<Self, AssignmentError> {
        Self::with_connect_ip_requirement(expected_generation, true)
    }

    fn with_connect_ip_requirement(
        expected_generation: u64,
        connect_ip_required: bool,
    ) -> Result<Self, AssignmentError> {
        Ok(Self {
            receiver: AssignmentReceiver::new(expected_generation)?,
            failure: None,
            connect_ip_addresses: None,
            connect_ip_routes: None,
            connect_ip_required,
            connect_ip_ready: !connect_ip_required,
        })
    }

    /// Feed one capsule and retain the first terminal failure.
    pub fn receive(&mut self, capsule_type: u64, payload: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        let result = match capsule_type {
            CONNECT_IP_ADDRESS_ASSIGN_CAPSULE_TYPE => decode_connect_ip_addresses(payload)
                .map(|addresses| self.connect_ip_addresses = Some(addresses)),
            CONNECT_IP_ROUTE_ADVERTISEMENT_CAPSULE_TYPE => decode_connect_ip_routes(payload)
                .map(|routes| self.connect_ip_routes = Some(routes)),
            _ => self.receiver.receive(capsule_type, payload).map(|_| ()),
        }
        .and_then(|()| self.refresh_connect_ip_state());
        if let Err(error) = result {
            self.connect_ip_ready = false;
            self.failure = Some(error);
        }
    }

    fn refresh_connect_ip_state(&mut self) -> Result<(), AssignmentError> {
        if self.receiver.assignment().is_none() {
            self.connect_ip_ready = false;
            return Ok(());
        }
        match (&self.connect_ip_addresses, &self.connect_ip_routes) {
            (None, None) => {
                self.connect_ip_ready = !self.connect_ip_required;
                Ok(())
            }
            (Some(_), Some(_)) => {
                self.validate_connect_ip_assignment()?;
                self.connect_ip_ready = true;
                Ok(())
            }
            _ => {
                self.connect_ip_ready = false;
                Ok(())
            }
        }
    }

    /// Return the accepted assignment, if one exists.
    pub fn assignment(&self) -> Option<&ClientAssignment> {
        self.connect_ip_ready.then(|| self.receiver.assignment()).flatten()
    }

    /// Return the first terminal reception failure, if one exists.
    pub fn failure(&self) -> Option<&AssignmentError> {
        self.failure.as_ref()
    }

    fn validate_connect_ip_assignment(&self) -> Result<(), AssignmentError> {
        let (Some(addresses), Some(routes)) =
            (self.connect_ip_addresses.as_ref(), self.connect_ip_routes.as_ref())
        else {
            return Ok(());
        };
        let assignment = self
            .receiver
            .assignment()
            .ok_or(AssignmentError::InvalidConnectIpControl("private assignment is missing"))?;
        let expected_address_count =
            usize::from(assignment.ipv4.is_some()) + usize::from(assignment.ipv6.is_some());
        if addresses.len() != expected_address_count || routes.len() != expected_address_count {
            return Err(AssignmentError::ConnectIpAssignmentMismatch);
        }
        if let Some(ipv4) = assignment.ipv4 {
            if !addresses.contains(&(IpAddr::V4(ipv4.address), 32))
                || !routes.contains(&(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V4(Ipv4Addr::BROADCAST),
                    0,
                ))
            {
                return Err(AssignmentError::ConnectIpAssignmentMismatch);
            }
        }
        if let Some(ipv6) = assignment.ipv6 {
            if !addresses.contains(&(IpAddr::V6(ipv6.address), 128))
                || !routes.contains(&(
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::from(u128::MAX)),
                    0,
                ))
            {
                return Err(AssignmentError::ConnectIpAssignmentMismatch);
            }
        }
        Ok(())
    }
}

fn decode_connect_ip_addresses(payload: &[u8]) -> Result<Vec<(IpAddr, u8)>, AssignmentError> {
    let mut reader = Reader::new(payload);
    let mut addresses = Vec::new();
    while reader.remaining() > 0 {
        if addresses.len() >= 8 {
            return Err(AssignmentError::InvalidConnectIpControl("too many assigned addresses"));
        }
        let request_id = reader.quic_varint()?;
        if request_id != 0 {
            return Err(AssignmentError::InvalidConnectIpControl(
                "server address assignment request id must be zero",
            ));
        }
        let address = reader.ip()?;
        let prefix = reader.u8()?;
        if (address.is_ipv4() && prefix > 32) || (address.is_ipv6() && prefix > 128) {
            return Err(AssignmentError::InvalidConnectIpControl("invalid address prefix"));
        }
        if !ip_prefix_is_canonical(address, prefix) {
            return Err(AssignmentError::InvalidConnectIpControl(
                "assigned address has non-zero bits after its prefix",
            ));
        }
        if addresses.contains(&(address, prefix)) {
            return Err(AssignmentError::InvalidConnectIpControl("duplicate assigned address"));
        }
        addresses.push((address, prefix));
    }
    Ok(addresses)
}

fn decode_connect_ip_routes(payload: &[u8]) -> Result<Vec<(IpAddr, IpAddr, u8)>, AssignmentError> {
    let mut reader = Reader::new(payload);
    let mut routes = Vec::new();
    while reader.remaining() > 0 {
        if routes.len() >= 8 {
            return Err(AssignmentError::InvalidConnectIpControl("too many advertised routes"));
        }
        let family = reader.u8()?;
        let (start, end) = match family {
            4 => (IpAddr::V4(reader.ipv4()?), IpAddr::V4(reader.ipv4()?)),
            6 => (IpAddr::V6(reader.ipv6()?), IpAddr::V6(reader.ipv6()?)),
            family => return Err(AssignmentError::InvalidIpFamily(family)),
        };
        let protocol = reader.u8()?;
        if ip_numeric(start) > ip_numeric(end) {
            return Err(AssignmentError::InvalidConnectIpControl("invalid or duplicate route"));
        }
        for (previous_start, previous_end, previous_protocol) in &routes {
            let previous_family = ip_family_order(*previous_start);
            let family_order = ip_family_order(start);
            if family_order < previous_family
                || (family_order == previous_family && protocol < *previous_protocol)
                || (family_order == previous_family
                    && protocol == *previous_protocol
                    && ip_numeric(start) <= ip_numeric(*previous_end))
            {
                return Err(AssignmentError::InvalidConnectIpControl(
                    "routes are not strictly ordered and disjoint",
                ));
            }
            if family_order == previous_family
                && (protocol == 0 || *previous_protocol == 0)
                && ip_ranges_overlap(*previous_start, *previous_end, start, end)
            {
                return Err(AssignmentError::InvalidConnectIpControl(
                    "all-protocol route overlaps another route",
                ));
            }
        }
        routes.push((start, end, protocol));
    }
    Ok(routes)
}

fn ip_prefix_is_canonical(address: IpAddr, prefix: u8) -> bool {
    let (value, width) = match address {
        IpAddr::V4(address) => (u128::from(u32::from(address)), 32),
        IpAddr::V6(address) => (u128::from(address), 128),
    };
    let host_bits = width - u32::from(prefix);
    match host_bits {
        0 => true,
        128 => value == 0,
        _ => value & ((1u128 << host_bits) - 1) == 0,
    }
}

fn ip_family_order(address: IpAddr) -> u8 {
    if address.is_ipv4() {
        4
    } else {
        6
    }
}

fn ip_ranges_overlap(
    left_start: IpAddr,
    left_end: IpAddr,
    right_start: IpAddr,
    right_end: IpAddr,
) -> bool {
    ip_numeric(left_start) <= ip_numeric(right_end)
        && ip_numeric(right_start) <= ip_numeric(left_end)
}

fn ip_numeric(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

/// Assignment codec and state-machine failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignmentError {
    /// The payload ended before the requested field was available.
    Truncated,
    /// The payload exceeded the hard bound.
    PayloadTooLarge(usize),
    /// The payload has bytes after the defined schema.
    TrailingBytes(usize),
    /// A future or unsupported wire version was received.
    UnsupportedVersion(u8),
    /// Unknown flag bits were set.
    InvalidFlags(u8),
    /// The reserved schema byte was not zero.
    NonZeroReservedField,
    /// The address-family order value is unknown.
    InvalidFamilyOrder(u8),
    /// Address presence and order disagree.
    FamilyOrderMismatch { expected: AddressFamilyOrder, actual: AddressFamilyOrder },
    /// The assignment contains no enabled address family.
    NoAddressFamily,
    /// An enabled assignment has an invalid MTU.
    InvalidMtu(u16),
    /// An IPv6 assignment has an MTU below the IPv6 minimum.
    Ipv6MtuTooSmall(u16),
    /// The IPv4 prefix is outside 0..=32.
    InvalidIpv4Prefix(u8),
    /// The IPv6 prefix is outside 0..=128.
    InvalidIpv6Prefix(u8),
    /// A disabled assignment carried enabled-only data.
    DisabledPayloadNotEmpty,
    /// DNS count exceeds the bounded schema limit.
    TooManyDnsServers(usize),
    /// A DNS server was repeated.
    DuplicateDnsServer(IpAddr),
    /// DNS presence flag and count disagree.
    DnsFlagMismatch,
    /// A session or generation identity was zero.
    InvalidIdentity(&'static str),
    /// The assignment belongs to another reconnect generation.
    UnexpectedGeneration { expected: u64, actual: u64 },
    /// A second assignment changed already accepted connection state.
    ConflictingAssignment,
    /// An IP family discriminator is unknown.
    InvalidIpFamily(u8),
    /// An RFC 9484 control capsule violates its bounded grammar or state contract.
    InvalidConnectIpControl(&'static str),
    /// RFC 9484 address/route state disagrees with the authenticated operational assignment.
    ConnectIpAssignmentMismatch,
}

impl fmt::Display for AssignmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AssignmentError {}

struct Reader<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self { payload, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AssignmentError> {
        let end = self.offset.checked_add(length).ok_or(AssignmentError::Truncated)?;
        let bytes = self.payload.get(self.offset..end).ok_or(AssignmentError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, AssignmentError> {
        Ok(*self.take(1)?.first().ok_or(AssignmentError::Truncated)?)
    }

    fn u16(&mut self) -> Result<u16, AssignmentError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, AssignmentError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| AssignmentError::Truncated)?))
    }

    fn ipv4(&mut self) -> Result<Ipv4Addr, AssignmentError> {
        let bytes = self.take(4)?;
        Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }

    fn ipv6(&mut self) -> Result<Ipv6Addr, AssignmentError> {
        let bytes = self.take(16)?;
        let octets: [u8; 16] = bytes.try_into().map_err(|_| AssignmentError::Truncated)?;
        Ok(Ipv6Addr::from(octets))
    }

    fn ip(&mut self) -> Result<IpAddr, AssignmentError> {
        match self.u8()? {
            4 => Ok(IpAddr::V4(self.ipv4()?)),
            6 => Ok(IpAddr::V6(self.ipv6()?)),
            family => Err(AssignmentError::InvalidIpFamily(family)),
        }
    }

    fn remaining(&self) -> usize {
        self.payload.len().saturating_sub(self.offset)
    }

    fn quic_varint(&mut self) -> Result<u64, AssignmentError> {
        let first = self.u8()?;
        let length = 1usize << usize::from(first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(length - 1)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    fn finish(&self) -> Result<(), AssignmentError> {
        if self.offset == self.payload.len() {
            Ok(())
        } else {
            Err(AssignmentError::TrailingBytes(self.payload.len() - self.offset))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dual_stack() -> ClientAssignment {
        ClientAssignment::enabled(
            7,
            11,
            Some(AssignedIpv4 { address: Ipv4Addr::new(10, 8, 0, 2), prefix: 24 }),
            Some(AssignedIpv6 { address: Ipv6Addr::LOCALHOST, prefix: 64 }),
            1500,
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V6(Ipv6Addr::LOCALHOST)],
        )
        .expect("valid dual-stack assignment")
    }

    fn encode_test_route(start: IpAddr, end: IpAddr, protocol: u8, out: &mut Vec<u8>) {
        encode_ip(out, start);
        match end {
            IpAddr::V4(address) => out.extend_from_slice(&address.octets()),
            IpAddr::V6(address) => out.extend_from_slice(&address.octets()),
        }
        out.push(protocol);
    }

    #[test]
    fn dual_stack_round_trip_preserves_order_and_dns() {
        let assignment = dual_stack();
        let decoded =
            ClientAssignment::decode(&assignment.encode().expect("encode")).expect("decode");
        assert_eq!(decoded, assignment);
        assert_eq!(decoded.family_order, AddressFamilyOrder::Ipv4ThenIpv6);
    }

    #[test]
    fn ipv4_and_ipv6_only_assignments_round_trip() {
        let ipv4 = ClientAssignment::enabled(
            1,
            2,
            Some(AssignedIpv4 { address: Ipv4Addr::new(10, 0, 0, 2), prefix: 24 }),
            None,
            576,
            Vec::new(),
        )
        .expect("IPv4 assignment");
        let ipv6 = ClientAssignment::enabled(
            1,
            2,
            None,
            Some(AssignedIpv6 { address: Ipv6Addr::LOCALHOST, prefix: 128 }),
            1280,
            Vec::new(),
        )
        .expect("IPv6 assignment");
        assert_eq!(ClientAssignment::decode(&ipv4.encode().expect("encode")), Ok(ipv4));
        assert_eq!(ClientAssignment::decode(&ipv6.encode().expect("encode")), Ok(ipv6));
    }

    #[test]
    fn disabled_assignment_is_explicit_and_empty() {
        let assignment = ClientAssignment::disabled(9, 3).expect("disabled assignment");
        let decoded =
            ClientAssignment::decode(&assignment.encode().expect("encode")).expect("decode");
        assert_eq!(decoded.mode, AssignmentMode::Disabled);
        assert_eq!(decoded.family_order, AddressFamilyOrder::None);
        assert!(decoded.ipv4.is_none());
        assert!(decoded.ipv6.is_none());
    }

    #[test]
    fn malformed_payloads_fail_closed() {
        let assignment = dual_stack();
        let mut payload = assignment.encode().expect("encode");
        payload[0] = CLIENT_ASSIGNMENT_VERSION + 1;
        assert!(matches!(
            ClientAssignment::decode(&payload),
            Err(AssignmentError::UnsupportedVersion(_))
        ));

        let mut payload = assignment.encode().expect("encode");
        payload[3] = 1;
        assert_eq!(ClientAssignment::decode(&payload), Err(AssignmentError::NonZeroReservedField));

        let mut payload = assignment.encode().expect("encode");
        payload.push(0);
        assert!(matches!(
            ClientAssignment::decode(&payload),
            Err(AssignmentError::TrailingBytes(1))
        ));

        let payload = vec![0u8; MAX_CLIENT_ASSIGNMENT_PAYLOAD + 1];
        assert!(matches!(
            ClientAssignment::decode(&payload),
            Err(AssignmentError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn duplicate_and_conflicting_assignments_are_distinguished() {
        let assignment = dual_stack();
        let payload = assignment.encode().expect("encode");
        let mut receiver = AssignmentReceiver::new(11).expect("receiver");
        assert_eq!(
            receiver.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &payload),
            Ok(AssignmentReceipt::Accepted)
        );
        assert_eq!(
            receiver.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &payload),
            Ok(AssignmentReceipt::Duplicate)
        );
        let conflicting = ClientAssignment::enabled(
            7,
            11,
            Some(AssignedIpv4 { address: Ipv4Addr::new(10, 8, 0, 3), prefix: 24 }),
            Some(AssignedIpv6 { address: Ipv6Addr::LOCALHOST, prefix: 64 }),
            1500,
            vec![],
        )
        .expect("conflicting assignment");
        assert_eq!(
            receiver
                .receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &conflicting.encode().expect("encode")),
            Err(AssignmentError::ConflictingAssignment)
        );
        assert_eq!(
            receiver.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE + 1, &payload),
            Ok(AssignmentReceipt::Ignored)
        );
    }

    #[test]
    fn callback_reception_retains_first_failure_and_does_not_mutate_afterward() {
        let assignment = dual_stack();
        let mut reception = AssignmentReception::new(11).expect("reception");
        let mut malformed = assignment.encode().expect("encode");
        malformed[0] = CLIENT_ASSIGNMENT_VERSION + 1;
        reception.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &malformed);
        assert_eq!(reception.failure(), Some(&AssignmentError::UnsupportedVersion(2)));
        reception.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &assignment.encode().expect("encode"));
        assert!(reception.assignment().is_none());
    }

    #[test]
    fn assignment_receiver_does_not_confuse_data_or_context_with_assignment() {
        let mut receiver = AssignmentReceiver::new(11).expect("receiver");
        assert_eq!(receiver.receive(0x00, &[0x45, 0, 0, 20]), Ok(AssignmentReceipt::Ignored));
        assert_eq!(receiver.receive(0x30, &[0, 0]), Ok(AssignmentReceipt::Ignored));
        assert!(receiver.assignment().is_none());
    }

    #[test]
    fn connect_ip_capsules_assign_addresses_and_advertise_full_tunnel_routes() {
        let capsules = dual_stack().encode_connect_ip_capsules().expect("RFC 9484 capsules");
        assert_eq!(capsules.len(), 2);
        assert_eq!(capsules[0].0, CONNECT_IP_ADDRESS_ASSIGN_CAPSULE_TYPE);
        assert_eq!(capsules[0].1[0], 0);
        assert!(capsules[0].1.contains(&4));
        assert!(capsules[0].1.contains(&6));
        assert_eq!(capsules[1].0, CONNECT_IP_ROUTE_ADVERTISEMENT_CAPSULE_TYPE);
        assert_eq!(capsules[1].1.first(), Some(&4));
        assert!(capsules[1].1.contains(&6));
        assert_eq!(
            decode_connect_ip_addresses(&capsules[0].1),
            Ok(vec![
                (IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)), 32),
                (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            ])
        );
    }

    #[test]
    fn connect_ip_control_state_must_match_the_authenticated_assignment() {
        let assignment = dual_stack();
        let capsules = assignment.encode_connect_ip_capsules().expect("RFC 9484 capsules");
        let mut reception =
            AssignmentReception::new_connect_ip(assignment.generation).expect("reception");
        reception.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &assignment.encode().expect("encode"));
        assert!(reception.assignment().is_none());
        reception.receive(capsules[0].0, &capsules[0].1);
        assert!(reception.assignment().is_none());
        reception.receive(capsules[1].0, &capsules[1].1);
        assert!(reception.failure().is_none());
        assert_eq!(reception.assignment(), Some(&assignment));

        let mut mismatched =
            AssignmentReception::new_connect_ip(assignment.generation).expect("reception");
        let mut wrong_addresses = capsules[0].1.clone();
        wrong_addresses[2] ^= 1;
        mismatched
            .receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &assignment.encode().expect("assignment"));
        mismatched.receive(CONNECT_IP_ADDRESS_ASSIGN_CAPSULE_TYPE, &wrong_addresses);
        mismatched.receive(CONNECT_IP_ROUTE_ADVERTISEMENT_CAPSULE_TYPE, &capsules[1].1);
        assert_eq!(mismatched.failure(), Some(&AssignmentError::ConnectIpAssignmentMismatch));
        assert!(mismatched.assignment().is_none());
    }

    #[test]
    fn legacy_reception_does_not_require_connect_ip_capsules() {
        let assignment = dual_stack();
        let mut reception = AssignmentReception::new(assignment.generation).expect("reception");
        reception.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &assignment.encode().expect("encode"));
        assert_eq!(reception.assignment(), Some(&assignment));
    }

    #[test]
    fn connect_ip_withdrawals_are_valid_but_cannot_authorize_an_active_assignment() {
        assert_eq!(decode_connect_ip_addresses(&[]), Ok(Vec::new()));
        assert_eq!(decode_connect_ip_routes(&[]), Ok(Vec::new()));

        let assignment = dual_stack();
        let mut reception =
            AssignmentReception::new_connect_ip(assignment.generation).expect("reception");
        reception.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &assignment.encode().expect("encode"));
        reception.receive(CONNECT_IP_ADDRESS_ASSIGN_CAPSULE_TYPE, &[]);
        reception.receive(CONNECT_IP_ROUTE_ADVERTISEMENT_CAPSULE_TYPE, &[]);
        assert_eq!(reception.failure(), Some(&AssignmentError::ConnectIpAssignmentMismatch));
        assert!(reception.assignment().is_none());
    }

    #[test]
    fn connect_ip_addresses_require_canonical_prefix_bits() {
        let non_canonical = [0, 4, 10, 0, 0, 2, 24];
        assert_eq!(
            decode_connect_ip_addresses(&non_canonical),
            Err(AssignmentError::InvalidConnectIpControl(
                "assigned address has non-zero bits after its prefix"
            ))
        );
        let canonical_zero_prefix = [0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_connect_ip_addresses(&canonical_zero_prefix),
            Ok(vec![(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)])
        );
    }

    #[test]
    fn connect_ip_routes_require_rfc_ordering_and_disjoint_ranges() {
        let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let last = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));
        let mut descending_protocols = Vec::new();
        encode_test_route(first, last, 17, &mut descending_protocols);
        encode_test_route(first, last, 6, &mut descending_protocols);
        assert!(decode_connect_ip_routes(&descending_protocols).is_err());

        let mut overlapping_all_protocol = Vec::new();
        encode_test_route(first, last, 0, &mut overlapping_all_protocol);
        encode_test_route(first, last, 6, &mut overlapping_all_protocol);
        assert_eq!(
            decode_connect_ip_routes(&overlapping_all_protocol),
            Err(AssignmentError::InvalidConnectIpControl(
                "all-protocol route overlaps another route"
            ))
        );
    }

    #[test]
    fn malformed_connect_ip_control_capsules_fail_closed() {
        let assignment = dual_stack();
        let mut reception = AssignmentReception::new(assignment.generation).expect("reception");
        reception.receive(CONNECT_IP_ADDRESS_ASSIGN_CAPSULE_TYPE, &[0, 4, 10]);
        assert!(matches!(reception.failure(), Some(AssignmentError::Truncated)));
    }

    #[test]
    fn stale_generation_is_rejected_before_state_change() {
        let assignment = ClientAssignment::enabled(
            7,
            12,
            Some(AssignedIpv4 { address: Ipv4Addr::new(10, 8, 0, 2), prefix: 24 }),
            None,
            1500,
            Vec::new(),
        )
        .expect("assignment");
        let mut receiver = AssignmentReceiver::new(11).expect("receiver");
        assert_eq!(
            receiver.receive(CLIENT_ASSIGNMENT_CAPSULE_TYPE, &assignment.encode().expect("encode")),
            Err(AssignmentError::UnexpectedGeneration { expected: 11, actual: 12 })
        );
        assert!(receiver.assignment().is_none());
    }
}
