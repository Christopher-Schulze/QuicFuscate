//! Stateless QUIC Retry ownership for enhanced DDoS admission.

use crate::crypto::hkdf::hmac_sha256;
use crate::secret::SecretBytes;
use crate::transport::packet::{append_retry_tag, format_header, parse_header, Header};
use crate::transport::{PacketType, MAX_CONN_ID_LEN};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RETRY_TOKEN_MAGIC: &[u8; 4] = b"QFRT";
const RETRY_TOKEN_VERSION: u8 = 1;
const RETRY_TOKEN_TAG_LEN: usize = 32;
const MAX_RETRY_CREDENTIAL_LEN: usize = 64;
const MAX_RETRY_TOKEN_LEN: usize = 160;
const MAX_RETRY_CLOCK_SKEW_SECS: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetryTokenClaims {
    pub(crate) original_dcid: Vec<u8>,
    pub(crate) credential: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryTokenError {
    NotRetryToken,
    Malformed,
    InvalidTag,
    AddressMismatch,
    ConnectionIdMismatch,
    Expired,
    IssuedInFuture,
    UnsupportedVersion,
}

impl fmt::Display for RetryTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NotRetryToken => "not a QuicFuscate Retry token",
            Self::Malformed => "malformed Retry token",
            Self::InvalidTag => "invalid Retry token authentication tag",
            Self::AddressMismatch => "Retry token source address mismatch",
            Self::ConnectionIdMismatch => "Retry token connection ID mismatch",
            Self::Expired => "Retry token expired",
            Self::IssuedInFuture => "Retry token issued in the future",
            Self::UnsupportedVersion => "unsupported Retry token version",
        };
        formatter.write_str(message)
    }
}

pub(crate) struct RetryIssue {
    pub(crate) packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DdosDropReason {
    GlobalLimit,
    GeoIp,
    Blacklist,
    PerIpLimit,
    MalformedInitial,
    InvalidRetry,
}

pub(crate) enum IncomingDatagramAdmission {
    Allow,
    RetryValidated,
    Drop(DdosDropReason),
    Retry(Vec<u8>),
}

pub(crate) struct RetryTokenManager {
    secret: SecretBytes,
    lifetime: Duration,
}

impl RetryTokenManager {
    pub(crate) fn new(lifetime: Duration) -> Result<Self, String> {
        if lifetime.is_zero() {
            return Err("Retry token lifetime must be greater than zero".to_string());
        }
        let mut secret = SecretBytes::zeroed(32, "server_retry_token_secret");
        crate::transport::rand::rand_bytes(secret.as_mut_slice());
        Ok(Self { secret, lifetime })
    }

    pub(crate) fn is_retry_token(token: &[u8]) -> bool {
        token.starts_with(RETRY_TOKEN_MAGIC)
    }

    pub(crate) fn issue_for_initial(
        &self,
        packet: &[u8],
        source_ip: IpAddr,
    ) -> Result<RetryIssue, String> {
        let (header, _) =
            parse_header(packet, 0).map_err(|error| format!("Initial parse failed: {error}"))?;
        if header.ty != PacketType::Initial {
            return Err("Retry can only be issued for an Initial packet".to_string());
        }
        if header.dcid.is_empty()
            || header.dcid.len() > MAX_CONN_ID_LEN
            || header.scid.len() > MAX_CONN_ID_LEN
        {
            return Err("Initial connection ID length is invalid".to_string());
        }

        let mut retry_scid = vec![0u8; MAX_CONN_ID_LEN];
        crate::transport::rand::rand_bytes(&mut retry_scid);
        let credential = header.token.as_deref().unwrap_or(&[]);
        let token =
            self.seal(source_ip, &header.dcid, &retry_scid, credential, current_epoch_secs())?;
        let retry_header = Header {
            ty: PacketType::Retry,
            version: header.version,
            dcid: header.scid,
            scid: retry_scid,
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(token),
            versions: None,
            key_phase: false,
        };
        let mut storage = [0u8; 256];
        let header_len = format_header(&retry_header, &mut storage)
            .map_err(|error| format!("Retry header format failed: {error}"))?;
        let mut response = storage[..header_len].to_vec();
        append_retry_tag(&mut response, &header.dcid, header.version)
            .map_err(|error| format!("Retry integrity tag failed: {error}"))?;
        Ok(RetryIssue { packet: response })
    }

    pub(crate) fn validate(
        &self,
        token: &[u8],
        source_ip: IpAddr,
        current_dcid: &[u8],
    ) -> Result<RetryTokenClaims, RetryTokenError> {
        self.validate_at(token, source_ip, current_dcid, current_epoch_secs())
    }

    fn seal(
        &self,
        source_ip: IpAddr,
        original_dcid: &[u8],
        retry_scid: &[u8],
        credential: &[u8],
        issued_at_secs: u64,
    ) -> Result<Vec<u8>, String> {
        if original_dcid.is_empty()
            || original_dcid.len() > MAX_CONN_ID_LEN
            || retry_scid.is_empty()
            || retry_scid.len() > MAX_CONN_ID_LEN
            || credential.len() > MAX_RETRY_CREDENTIAL_LEN
        {
            return Err("Retry token input exceeds the bounded wire contract".to_string());
        }

        let ip_bytes: Vec<u8> = match source_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let mut token = Vec::with_capacity(MAX_RETRY_TOKEN_LEN);
        token.extend_from_slice(RETRY_TOKEN_MAGIC);
        token.push(RETRY_TOKEN_VERSION);
        token.extend_from_slice(&issued_at_secs.to_be_bytes());
        token.push(ip_bytes.len() as u8);
        token.extend_from_slice(&ip_bytes);
        token.push(original_dcid.len() as u8);
        token.extend_from_slice(original_dcid);
        token.push(retry_scid.len() as u8);
        token.extend_from_slice(retry_scid);
        token.push(credential.len() as u8);
        token.extend_from_slice(credential);
        let tag = hmac_sha256(self.secret.as_slice(), &token);
        token.extend_from_slice(&tag);
        if token.len() > MAX_RETRY_TOKEN_LEN {
            return Err("Retry token exceeds the maximum encoded length".to_string());
        }
        Ok(token)
    }

    fn validate_at(
        &self,
        token: &[u8],
        source_ip: IpAddr,
        current_dcid: &[u8],
        now_secs: u64,
    ) -> Result<RetryTokenClaims, RetryTokenError> {
        if !Self::is_retry_token(token) {
            return Err(RetryTokenError::NotRetryToken);
        }
        if token.len() > MAX_RETRY_TOKEN_LEN
            || token.len() < RETRY_TOKEN_MAGIC.len() + 1 + 8 + RETRY_TOKEN_TAG_LEN
        {
            return Err(RetryTokenError::Malformed);
        }
        let body_len = token.len() - RETRY_TOKEN_TAG_LEN;
        let expected_tag = hmac_sha256(self.secret.as_slice(), &token[..body_len]);
        if !constant_time_eq(&expected_tag, &token[body_len..]) {
            return Err(RetryTokenError::InvalidTag);
        }

        let mut cursor = RETRY_TOKEN_MAGIC.len();
        let version = take_u8(token, &mut cursor, body_len)?;
        if version != RETRY_TOKEN_VERSION {
            return Err(RetryTokenError::UnsupportedVersion);
        }
        let issued_at_secs = take_u64(token, &mut cursor, body_len)?;
        let encoded_ip = take_bounded_bytes(token, &mut cursor, body_len, 16)?;
        let original_dcid =
            take_bounded_bytes(token, &mut cursor, body_len, MAX_CONN_ID_LEN)?.to_vec();
        let retry_scid = take_bounded_bytes(token, &mut cursor, body_len, MAX_CONN_ID_LEN)?;
        let credential =
            take_bounded_bytes(token, &mut cursor, body_len, MAX_RETRY_CREDENTIAL_LEN)?.to_vec();
        if cursor != body_len || original_dcid.is_empty() || retry_scid.is_empty() {
            return Err(RetryTokenError::Malformed);
        }
        if encoded_ip != source_ip_bytes(source_ip).as_slice() {
            return Err(RetryTokenError::AddressMismatch);
        }
        if retry_scid != current_dcid {
            return Err(RetryTokenError::ConnectionIdMismatch);
        }
        if issued_at_secs > now_secs.saturating_add(MAX_RETRY_CLOCK_SKEW_SECS) {
            return Err(RetryTokenError::IssuedInFuture);
        }
        if now_secs.saturating_sub(issued_at_secs) > self.lifetime.as_secs() {
            return Err(RetryTokenError::Expired);
        }
        Ok(RetryTokenClaims { original_dcid, credential })
    }
}

fn take_u8(token: &[u8], cursor: &mut usize, body_len: usize) -> Result<u8, RetryTokenError> {
    let value = *token.get(*cursor).ok_or(RetryTokenError::Malformed)?;
    *cursor += 1;
    if *cursor > body_len {
        return Err(RetryTokenError::Malformed);
    }
    Ok(value)
}

fn take_u64(token: &[u8], cursor: &mut usize, body_len: usize) -> Result<u64, RetryTokenError> {
    if body_len.saturating_sub(*cursor) < 8 {
        return Err(RetryTokenError::Malformed);
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&token[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_be_bytes(bytes))
}

fn take_bounded_bytes<'a>(
    token: &'a [u8],
    cursor: &mut usize,
    body_len: usize,
    maximum: usize,
) -> Result<&'a [u8], RetryTokenError> {
    let length = take_u8(token, cursor, body_len)? as usize;
    if length > maximum || body_len.saturating_sub(*cursor) < length {
        return Err(RetryTokenError::Malformed);
    }
    let bytes = &token[*cursor..*cursor + length];
    *cursor += length;
    Ok(bytes)
}

fn source_ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn constant_time_eq(expected: &[u8; RETRY_TOKEN_TAG_LEN], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(actual) {
        difference |= left ^ right;
    }
    difference == 0
}

fn current_epoch_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> RetryTokenManager {
        RetryTokenManager::new(Duration::from_secs(10)).unwrap()
    }

    #[test]
    fn retry_token_roundtrip_binds_address_and_connection_id() {
        let manager = manager();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let odcid = [1, 2, 3, 4];
        let retry_scid = [5, 6, 7, 8];
        let credential = b"a1b2c3d4e5f6";
        let token = manager.seal(ip, &odcid, &retry_scid, credential, 100).unwrap();

        assert_eq!(
            manager.validate_at(&token, ip, &retry_scid, 105).unwrap(),
            RetryTokenClaims { original_dcid: odcid.to_vec(), credential: credential.to_vec() }
        );
        assert_eq!(
            manager.validate_at(&token, "203.0.113.8".parse().unwrap(), &retry_scid, 105),
            Err(RetryTokenError::AddressMismatch)
        );
        assert_eq!(
            manager.validate_at(&token, ip, &[9], 105),
            Err(RetryTokenError::ConnectionIdMismatch)
        );
    }

    #[test]
    fn retry_token_rejects_tamper_expiry_future_and_malformed_lengths() {
        let manager = manager();
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let mut token = manager.seal(ip, &[1], &[2], b"a1b2c3d4e5f6", 100).unwrap();
        token[20] ^= 1;
        assert_eq!(manager.validate_at(&token, ip, &[2], 100), Err(RetryTokenError::InvalidTag));

        let token = manager.seal(ip, &[1], &[2], b"a1b2c3d4e5f6", 100).unwrap();
        assert_eq!(manager.validate_at(&token, ip, &[2], 111), Err(RetryTokenError::Expired));
        assert_eq!(manager.validate_at(&token, ip, &[2], 98), Err(RetryTokenError::IssuedInFuture));
        assert_eq!(
            manager.validate_at(RETRY_TOKEN_MAGIC, ip, &[2], 100),
            Err(RetryTokenError::Malformed)
        );
    }

    #[test]
    fn retry_packet_uses_rfc_integrity_and_carries_valid_claims() {
        let manager = manager();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let initial_header = Header {
            ty: PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid: vec![1, 2, 3, 4],
            scid: vec![5, 6, 7, 8],
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(b"a1b2c3d4e5f6".to_vec()),
            versions: None,
            key_phase: false,
        };
        let mut storage = [0u8; 128];
        let initial_len = format_header(&initial_header, &mut storage).unwrap();
        let issue = manager.issue_for_initial(&storage[..initial_len], ip).unwrap();
        let (retry, _) = parse_header(&issue.packet, 0).unwrap();

        assert_eq!(retry.ty, PacketType::Retry);
        assert_eq!(retry.dcid, initial_header.scid);
        crate::transport::packet::verify_retry_tag(
            &issue.packet,
            &initial_header.dcid,
            initial_header.version,
        )
        .unwrap();
        let claims = manager.validate(retry.token.as_deref().unwrap(), ip, &retry.scid).unwrap();
        assert_eq!(claims.original_dcid, initial_header.dcid);
        assert_eq!(claims.credential, b"a1b2c3d4e5f6");
    }
}
