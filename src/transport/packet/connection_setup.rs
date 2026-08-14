use super::*;

/// Creates a new client-side QUIC connection with the given parameters.
pub fn connect(
    _sni: Option<&str>,
    scid: &[u8],
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
) -> Result<crate::transport::Connection, ConnectionError> {
    connect_with_clock(
        _sni,
        scid,
        local,
        peer,
        config,
        crate::time_source::ProtocolClock::default(),
    )
}

/// Creates a client connection using an explicit protocol clock owner.
pub fn connect_with_clock(
    _sni: Option<&str>,
    scid: &[u8],
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
    clock: crate::time_source::ProtocolClock,
) -> Result<crate::transport::Connection, ConnectionError> {
    let mut conn = crate::transport::Connection::new_with_role_and_clock(
        scid,
        local,
        peer,
        config.clone(),
        false,
        clock,
    )?;

    // Client selects an unpredictable initial DCID (RFC 9000). This DCID is also the ODCID
    // used for Initial key derivation (RFC 9001).
    let mut dcid = [0u8; crate::transport::MAX_CONN_ID_LEN];
    crate::transport::rand::rand_bytes(&mut dcid);
    conn.set_initial_dcid(crate::transport::ConnectionId::from_ref(&dcid));

    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = std::sync::Arc::new(qf_fec::FecObserver::new());
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut()
        .set_stealth_mode(false, browser_profile)
        .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;

    Ok(conn)
}

/// Creates a new server-side QUIC connection accepting a client handshake.
pub fn accept(
    scid: &[u8],
    initial_key_dcid: Option<&[u8]>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
) -> Result<crate::transport::Connection, ConnectionError> {
    accept_with_clock(
        scid,
        initial_key_dcid,
        local,
        peer,
        config,
        crate::time_source::ProtocolClock::default(),
    )
}

/// Creates a server connection using an explicit protocol clock owner.
pub fn accept_with_clock(
    scid: &[u8],
    initial_key_dcid: Option<&[u8]>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
    clock: crate::time_source::ProtocolClock,
) -> Result<crate::transport::Connection, ConnectionError> {
    accept_with_clock_and_original(scid, initial_key_dcid, None, local, peer, config, clock)
}

/// Creates a server connection with the original client DCID retained separately from the
/// Initial key-derivation DCID. The distinction is required after a validated Retry.
pub fn accept_with_clock_and_original(
    scid: &[u8],
    initial_key_dcid: Option<&[u8]>,
    original_dcid: Option<&[u8]>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
    clock: crate::time_source::ProtocolClock,
) -> Result<crate::transport::Connection, ConnectionError> {
    // Create connection with server role
    // Record the Destination Connection ID from this Initial for RFC 9001
    // key derivation. After Retry this is the server's Retry SCID, not the
    // client's original destination connection ID.
    let mut conn = crate::transport::Connection::new_with_role_and_clock(
        scid,
        local,
        peer,
        config.clone(),
        true,
        clock,
    )?;
    if let Some(initial_key_dcid) = initial_key_dcid {
        conn.set_initial_dcid(crate::transport::ConnectionId::from_ref(initial_key_dcid));
    }
    if let Some(original_dcid) = original_dcid {
        conn.set_original_dcid(crate::transport::ConnectionId::from_ref(original_dcid));
    } else if let Some(initial_key_dcid) = initial_key_dcid {
        conn.set_original_dcid(crate::transport::ConnectionId::from_ref(initial_key_dcid));
    }
    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = std::sync::Arc::new(qf_fec::FecObserver::new());
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut()
        .set_stealth_mode(false, browser_profile)
        .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;

    Ok(conn)
}
