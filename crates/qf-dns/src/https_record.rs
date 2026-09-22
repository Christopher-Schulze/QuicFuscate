//! HTTPS/SVCB resource-record support for the ECH outer-hop path (TODO-1064).
//!
//! The client resolves the relay's `HTTPS` record over DoH before dialing the
//! configured MASQUE outer hop. When the record carries an `ech` SvcParam the
//! raw ECHConfigList bytes are handed to rustls; when it does not, the hop
//! connects without ECH. The wire-format `ech` value is already the binary
//! ECHConfigList — no base64 decode step applies (that encoding only exists in
//! zone-file presentation format).

use crate::{parse_dns_name, validate_dns_query_size, DNS_HEADER_SIZE};

/// SvcParam key for the ECHConfigList (RFC 9460 Section 8, "ech" = 5).
const SVC_PARAM_ECH: u16 = 5;
/// DNS resource-record type for HTTPS service binding.
const QTYPE_HTTPS: u16 = 65;
const DNS_CLASS_IN: u16 = 1;
/// Bound answer iteration so a corrupt count cannot drive an oversized scan.
const MAX_ANSWER_RRS: usize = 64;
/// Bound SvcParam iteration inside one HTTPS RDATA.
const MAX_SVC_PARAMS: usize = 64;
/// ECHConfigList payloads are a few hundred bytes; reject absurd values.
const MAX_ECH_BYTES: usize = 4096;

/// Builds a standard recursive-desired query for the HTTPS (type 65) record
/// of `name`. Returns `None` when the name cannot be encoded on the wire.
pub fn build_https_query(name: &str, query_id: u16) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&query_id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_qname(name.trim_end_matches('.'), &mut out)?;
    out.extend_from_slice(&QTYPE_HTTPS.to_be_bytes());
    out.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Some(out)
}

fn encode_qname(name: &str, out: &mut Vec<u8>) -> Option<()> {
    if name.is_empty() {
        return None;
    }
    let mut total = 1usize;
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        total += label.len() + 1;
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    if total > 255 {
        return None;
    }
    out.push(0);
    Some(())
}

/// Extracts the first `ech` SvcParam payload found on any HTTPS resource
/// record in the answer section of a DNS response.
///
/// `want_qtype`/`want_name` describe the issued query; the HTTPS record may
/// legitimately be owned by a CNAME target reached through the chain, so every
/// HTTPS answer is inspected rather than only exact owner-name matches.
/// Returns `None` when no HTTPS record advertises ECH, and also on malformed
/// responses (fail-closed: no ECH rather than a guessed config).
pub fn extract_ech_config_list(response: &[u8]) -> Option<Vec<u8>> {
    if validate_dns_query_size(response).is_err() || response.len() < DNS_HEADER_SIZE {
        return None;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;

    let mut cursor = DNS_HEADER_SIZE;
    for _ in 0..qdcount.min(MAX_ANSWER_RRS) {
        let parsed = parse_dns_name(response, cursor)?;
        cursor = parsed.end.checked_add(4)?; // QTYPE + QCLASS
    }

    for _ in 0..ancount.min(MAX_ANSWER_RRS) {
        let parsed = parse_dns_name(response, cursor)?;
        cursor = parsed.end;
        let rtype = read_u16(response, cursor)?;
        let rdlength = read_u16(response, cursor + 8)? as usize;
        let rdata_start = cursor.checked_add(10)?;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > response.len() {
            return None;
        }
        if rtype == QTYPE_HTTPS {
            if let Some(ech) = parse_https_rdata_ech(&response[rdata_start..rdata_end]) {
                return Some(ech);
            }
        }
        cursor = rdata_end;
    }
    None
}

fn parse_https_rdata_ech(rdata: &[u8]) -> Option<Vec<u8>> {
    // SvcPriority (2) + TargetName (uncompressed labels) + SvcParam list.
    if rdata.len() < 3 {
        return None;
    }
    let mut cursor = 2usize; // skip priority
    loop {
        let len = *rdata.get(cursor)? as usize;
        cursor += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            // SVCB target names must not be compressed (RFC 9460).
            return None;
        }
        cursor = cursor.checked_add(len)?;
        if cursor > rdata.len() {
            return None;
        }
    }
    for _ in 0..MAX_SVC_PARAMS {
        if cursor == rdata.len() {
            return None;
        }
        let key = read_u16(rdata, cursor)?;
        let len = read_u16(rdata, cursor + 2)? as usize;
        let value_start = cursor.checked_add(4)?;
        let value_end = value_start.checked_add(len)?;
        if value_end > rdata.len() {
            return None;
        }
        if key == SVC_PARAM_ECH && len > 0 && len <= MAX_ECH_BYTES {
            return Some(rdata[value_start..value_end].to_vec());
        }
        cursor = value_end;
    }
    None
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}
