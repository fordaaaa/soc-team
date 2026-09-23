//! TLS ClientHello parsing over a single TCP payload.
//!
//! Hand-rolled RFC 5246/8446 walker: one TLS record expected to carry one
//! ClientHello handshake. Big-endian multi-byte fields are read with slice
//! `.get()` bounds checks only.
//!
//! Never panics: truncated or bogus lengths degrade to `truncated: true`
//! with whatever fields were recoverable, or `None` when the bytes are not
//! a ClientHello at all.

/// TLS record header length in bytes (content_type + version + length).
const RECORD_HEADER_LEN: usize = 5;
/// Offset of the record content_type byte within the payload.
const RECORD_CONTENT_TYPE_OFFSET: usize = 0;
/// Offset of the 2-byte record length field within the payload.
const RECORD_LENGTH_OFFSET: usize = 3;
/// Handshake message header length in bytes (type + 3-byte length).
const HANDSHAKE_HEADER_LEN: usize = 4;
/// Offset of the handshake type byte within the payload.
const HANDSHAKE_TYPE_OFFSET: usize = 5;
/// Offset of the 3-byte handshake length field within the payload.
const HANDSHAKE_LENGTH_OFFSET: usize = 6;
/// Length of the client_version field in bytes.
const CLIENT_VERSION_LEN: usize = 2;
/// Length of the random field in bytes.
const RANDOM_LEN: usize = 32;
/// Length of the session_id length prefix in bytes.
const SESSION_ID_LEN_FIELD: usize = 1;
/// Length of the cipher_suites length prefix in bytes.
const CIPHER_SUITES_LEN_FIELD: usize = 2;
/// Length of the compression_methods length prefix in bytes.
const COMPRESSION_LEN_FIELD: usize = 1;
/// Length of the extensions total-length prefix in bytes.
const EXTENSIONS_LEN_FIELD: usize = 2;
/// Length of one extension header (type + length) in bytes.
const EXTENSION_HEADER_LEN: usize = 4;
/// Length of the ServerNameList total-length prefix in bytes.
const SERVER_NAME_LIST_LEN_FIELD: usize = 2;
/// Length of one ServerName entry header (type + length) in bytes.
const SERVER_NAME_ENTRY_HEADER_LEN: usize = 3;
/// Minimum bytes needed to even start a ClientHello (record + handshake).
const MIN_HELLO_PREFIX_LEN: usize = RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN;

/// Record content type for handshake.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// Handshake message type for ClientHello.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Extension type for server_name (RFC 6066).
const EXTENSION_SERVER_NAME: u16 = 0x0000;
/// ServerName type for host_name (RFC 6066).
const SERVER_NAME_HOST_NAME: u8 = 0x00;

/// At most this many cipher suites are retained (JA3 order preserved).
const MAX_CIPHER_SUITES: usize = 64;
/// At most this many extension types are retained (JA3 order preserved).
const MAX_EXTENSION_TYPES: usize = 32;
/// SNI host_name is capped at this many characters.
const MAX_SNI_CHARS: usize = 255;

/// Summary of a TLS ClientHello. Cipher/extension lists are kept (capped)
/// so JA3-style fingerprints can be computed later without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSummary {
    /// legacy_version field (e.g. 0x0303 = TLS 1.2).
    pub version: Option<u16>,
    /// server_name extension host_name, capped at 255 chars.
    pub sni: Option<String>,
    /// Offered cipher suites in order — at most the first 64.
    pub cipher_suites: Vec<u16>,
    /// Extension types in order — at most the first 32.
    pub extension_types: Vec<u16>,
    /// True when any declared length exceeded the bytes available
    /// (ClientHello spanning multiple segments).
    pub truncated: bool,
}

/// Parse a TLS record expected to contain a ClientHello handshake.
///
/// Returns None when it is not a handshake record / not a ClientHello /
/// too short to even start one. Partial data still returns Some with
/// `truncated: true` and whatever fields were recoverable. Never panics.
pub fn parse(payload: &[u8]) -> Option<TlsSummary> {
    if payload.len() < MIN_HELLO_PREFIX_LEN {
        return None;
    }
    let content_type = payload.get(RECORD_CONTENT_TYPE_OFFSET).copied()?;
    if content_type != CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    let record_len = get_u16(payload, RECORD_LENGTH_OFFSET)? as usize;
    let mut truncated = false;
    if let Some(after_record) = payload.len().checked_sub(RECORD_HEADER_LEN) {
        if record_len > after_record {
            truncated = true;
        }
    } else {
        truncated = true;
    }
    let hs_type = payload.get(HANDSHAKE_TYPE_OFFSET).copied()?;
    if hs_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }
    let hs_len = get_u24(payload, HANDSHAKE_LENGTH_OFFSET)?;
    if let Some(after_hs) = payload
        .len()
        .checked_sub(RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN)
    {
        if hs_len > after_hs {
            truncated = true;
        }
    } else {
        truncated = true;
    }

    let mut summary = TlsSummary {
        version: None,
        sni: None,
        cipher_suites: Vec::new(),
        extension_types: Vec::new(),
        truncated,
    };

    let mut pos = RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN;

    // client_version (2 bytes).
    let Some(next) = pos.checked_add(CLIENT_VERSION_LEN) else {
        summary.truncated = true;
        return Some(summary);
    };
    let version_slice = match payload.get(pos..next) {
        Some(s) => s,
        None => {
            summary.truncated = true;
            return Some(summary);
        }
    };
    let hi = version_slice.first().copied().unwrap_or(0);
    let lo = version_slice.get(1).copied().unwrap_or(0);
    summary.version = Some(u16::from_be_bytes([hi, lo]));
    pos = next;

    // random (32 bytes).
    let Some(next) = pos.checked_add(RANDOM_LEN) else {
        summary.truncated = true;
        return Some(summary);
    };
    if payload.get(pos..next).is_none() {
        summary.truncated = true;
        return Some(summary);
    }
    pos = next;

    // session_id: 1-byte length + bytes.
    let Some(after_len) = pos.checked_add(SESSION_ID_LEN_FIELD) else {
        summary.truncated = true;
        return Some(summary);
    };
    let sess_len = match payload.get(pos..after_len) {
        Some(s) => s.first().copied().unwrap_or(0) as usize,
        None => {
            summary.truncated = true;
            return Some(summary);
        }
    };
    pos = after_len;
    let Some(next) = pos.checked_add(sess_len) else {
        summary.truncated = true;
        return Some(summary);
    };
    if payload.get(pos..next).is_none() {
        summary.truncated = true;
        return Some(summary);
    }
    pos = next;

    // cipher_suites: 2-byte byte-count + u16 pairs.
    let Some(after_len) = pos.checked_add(CIPHER_SUITES_LEN_FIELD) else {
        summary.truncated = true;
        return Some(summary);
    };
    let cs_len_slice = match payload.get(pos..after_len) {
        Some(s) => s,
        None => {
            summary.truncated = true;
            return Some(summary);
        }
    };
    let cs_hi = cs_len_slice.first().copied().unwrap_or(0);
    let cs_lo = cs_len_slice.get(1).copied().unwrap_or(0);
    let cs_len = u16::from_be_bytes([cs_hi, cs_lo]) as usize;
    pos = after_len;
    let remaining = payload.len().saturating_sub(pos);
    if cs_len > remaining {
        summary.truncated = true;
    }
    let effective = cs_len.min(remaining);
    let pairs = effective / 2;
    let take = pairs.min(MAX_CIPHER_SUITES);
    for i in 0..take {
        let Some(off) = i.checked_mul(2) else { break };
        let Some(hi_off) = pos.checked_add(off) else {
            break;
        };
        let Some(lo_off) = hi_off.checked_add(1) else {
            break;
        };
        let hi = match payload.get(hi_off) {
            Some(b) => *b,
            None => {
                summary.truncated = true;
                break;
            }
        };
        let lo = match payload.get(lo_off) {
            Some(b) => *b,
            None => {
                summary.truncated = true;
                break;
            }
        };
        summary.cipher_suites.push(u16::from_be_bytes([hi, lo]));
    }
    if cs_len > remaining {
        // Cipher bytes were cut short: later offsets are unknowable.
        return Some(summary);
    }
    let Some(next) = pos.checked_add(cs_len) else {
        summary.truncated = true;
        return Some(summary);
    };
    pos = next;

    // compression_methods: 1-byte length + bytes.
    let Some(after_len) = pos.checked_add(COMPRESSION_LEN_FIELD) else {
        summary.truncated = true;
        return Some(summary);
    };
    let comp_len = match payload.get(pos..after_len) {
        Some(s) => s.first().copied().unwrap_or(0) as usize,
        None => {
            summary.truncated = true;
            return Some(summary);
        }
    };
    pos = after_len;
    let Some(next) = pos.checked_add(comp_len) else {
        summary.truncated = true;
        return Some(summary);
    };
    if payload.get(pos..next).is_none() {
        summary.truncated = true;
        return Some(summary);
    }
    pos = next;

    // extensions: 2-byte total length + TLVs. Absent extensions (no room
    // for the length prefix) means a hello without extensions.
    let Some(after_len) = pos.checked_add(EXTENSIONS_LEN_FIELD) else {
        summary.truncated = true;
        return Some(summary);
    };
    let ext_total_slice = match payload.get(pos..after_len) {
        Some(s) => s,
        None => {
            // No extensions field present (hello ended after compression):
            // not truncation, just no extensions.
            return Some(summary);
        }
    };
    let ext_hi = ext_total_slice.first().copied().unwrap_or(0);
    let ext_lo = ext_total_slice.get(1).copied().unwrap_or(0);
    let ext_total = u16::from_be_bytes([ext_hi, ext_lo]) as usize;
    pos = after_len;
    let remaining = payload.len().saturating_sub(pos);
    if ext_total > remaining {
        summary.truncated = true;
    }
    let walk_len = ext_total.min(remaining);
    let Some(walk_end) = pos.checked_add(walk_len) else {
        summary.truncated = true;
        return Some(summary);
    };
    let mut ext_pos = pos;
    while ext_pos < walk_end {
        // Need a full extension header.
        let Some(header_end) = ext_pos.checked_add(EXTENSION_HEADER_LEN) else {
            summary.truncated = true;
            break;
        };
        if header_end > walk_end {
            summary.truncated = true;
            break;
        }
        let ext_type = match get_u16(payload, ext_pos) {
            Some(t) => t,
            None => {
                summary.truncated = true;
                break;
            }
        };
        // Extension length field sits at ext_pos + 2 (after the 2-byte type).
        let ext_len = match ext_pos.checked_add(2).and_then(|off| get_u16(payload, off)) {
            Some(l) => l as usize,
            None => {
                summary.truncated = true;
                break;
            }
        };
        let Some(data_start) = ext_pos.checked_add(EXTENSION_HEADER_LEN) else {
            summary.truncated = true;
            break;
        };
        let data_remaining = walk_end.saturating_sub(data_start);
        let effective_len = ext_len.min(data_remaining);
        let data_overrun = ext_len > data_remaining;
        if summary.extension_types.len() < MAX_EXTENSION_TYPES {
            summary.extension_types.push(ext_type);
        }
        if ext_type == EXTENSION_SERVER_NAME && summary.sni.is_none() {
            let data_end = match data_start.checked_add(effective_len) {
                Some(e) => e,
                None => {
                    summary.truncated = true;
                    break;
                }
            };
            let ext_data = match payload.get(data_start..data_end) {
                Some(s) => s,
                None => {
                    summary.truncated = true;
                    break;
                }
            };
            let (name, sni_truncated) = parse_server_name(ext_data);
            if let Some(name) = name {
                summary.sni = Some(name);
            }
            if sni_truncated || data_overrun {
                summary.truncated = true;
            }
        } else if data_overrun {
            summary.truncated = true;
        }
        if data_overrun {
            break;
        }
        let Some(next) = data_start.checked_add(ext_len) else {
            summary.truncated = true;
            break;
        };
        if next > walk_end {
            summary.truncated = true;
            break;
        }
        ext_pos = next;
    }

    Some(summary)
}

/// Read a big-endian u16 at `offset` with bounds checking. Never panics.
fn get_u16(payload: &[u8], offset: usize) -> Option<u16> {
    let hi = payload.get(offset).copied()?;
    let lo_off = offset.checked_add(1)?;
    let lo = payload.get(lo_off).copied()?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Read a big-endian u24 at `offset` with bounds checking. Never panics.
fn get_u24(payload: &[u8], offset: usize) -> Option<usize> {
    let b0 = payload.get(offset).copied()? as usize;
    let o1 = offset.checked_add(1)?;
    let o2 = offset.checked_add(2)?;
    let b1 = payload.get(o1).copied()? as usize;
    let b2 = payload.get(o2).copied()? as usize;
    let v0 = b0.checked_shl(16)?;
    let v1 = b1.checked_shl(8)?;
    Some(v0 | v1 | b2)
}

/// Parse the data of a server_name extension, returning the first host_name
/// and whether any declared length overran the available bytes.
///
/// `ext_data` is exactly the bytes available for this extension (possibly a
/// truncated prefix). Never panics.
fn parse_server_name(ext_data: &[u8]) -> (Option<String>, bool) {
    let list_len_slice = match ext_data.get(0..SERVER_NAME_LIST_LEN_FIELD) {
        Some(s) => s,
        None => return (None, true),
    };
    let list_hi = list_len_slice.first().copied().unwrap_or(0);
    let list_lo = list_len_slice.get(1).copied().unwrap_or(0);
    let list_len = u16::from_be_bytes([list_hi, list_lo]) as usize;
    let remaining = ext_data.len().saturating_sub(SERVER_NAME_LIST_LEN_FIELD);
    let mut truncated = false;
    if list_len > remaining {
        truncated = true;
    }
    let walk_len = list_len.min(remaining);
    let Some(walk_end) = SERVER_NAME_LIST_LEN_FIELD.checked_add(walk_len) else {
        return (None, true);
    };
    let mut pos = SERVER_NAME_LIST_LEN_FIELD;
    while pos < walk_end {
        let Some(header_end) = pos.checked_add(SERVER_NAME_ENTRY_HEADER_LEN) else {
            truncated = true;
            break;
        };
        if header_end > walk_end {
            truncated = true;
            break;
        }
        let name_type = match ext_data.get(pos) {
            Some(b) => *b,
            None => {
                truncated = true;
                break;
            }
        };
        let name_len = match pos.checked_add(1).and_then(|off| get_u16(ext_data, off)) {
            Some(l) => l as usize,
            None => {
                truncated = true;
                break;
            }
        };
        let Some(name_start) = pos.checked_add(SERVER_NAME_ENTRY_HEADER_LEN) else {
            truncated = true;
            break;
        };
        let name_remaining = walk_end.saturating_sub(name_start);
        let effective = name_len.min(name_remaining);
        if name_len > name_remaining {
            truncated = true;
        }
        if name_type == SERVER_NAME_HOST_NAME {
            let Some(name_end) = name_start.checked_add(effective) else {
                truncated = true;
                break;
            };
            let host_bytes = match ext_data.get(name_start..name_end) {
                Some(s) => s,
                None => {
                    truncated = true;
                    break;
                }
            };
            let decoded = String::from_utf8_lossy(host_bytes);
            let capped = if decoded.chars().count() > MAX_SNI_CHARS {
                decoded.chars().take(MAX_SNI_CHARS).collect::<String>()
            } else {
                decoded.into_owned()
            };
            return (Some(capped), truncated || name_len > name_remaining);
        }
        let Some(next) = name_start.checked_add(effective) else {
            truncated = true;
            break;
        };
        if name_len > name_remaining {
            // Entry was cut short: offsets beyond this are unknowable.
            break;
        }
        pos = next;
    }
    (None, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a complete server_name extension TLV (type + length + data)
    /// for the given hostname bytes.
    fn build_sni_ext(hostname: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.push(SERVER_NAME_HOST_NAME);
        let name_len = hostname.len() as u16;
        entry.extend_from_slice(&name_len.to_be_bytes());
        entry.extend_from_slice(hostname);
        let mut list = Vec::new();
        let list_len = entry.len() as u16;
        list.extend_from_slice(&list_len.to_be_bytes());
        list.extend_from_slice(&entry);
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        let ext_len = list.len() as u16;
        ext.extend_from_slice(&ext_len.to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    /// Assemble a valid ClientHello byte vector (one TLS record) from parts.
    ///
    /// `sni_host` is wrapped via [`build_sni_ext`] and prepended to
    /// `extra_exts` (each `(type, data)`); pass `None` plus empty extras for
    /// a hello without extensions data beyond the length prefix.
    fn build_hello(
        version: u16,
        sni_host: Option<&[u8]>,
        ciphers: &[u16],
        extra_exts: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&[0xAA; RANDOM_LEN]);
        // Empty session_id.
        body.push(0x00);
        // Cipher suites.
        let cs_bytes = ciphers.len() * 2;
        body.extend_from_slice(&(cs_bytes as u16).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        // Compression: one null method.
        body.push(0x01);
        body.push(0x00);
        // Extensions.
        let mut exts = Vec::new();
        if let Some(host) = sni_host {
            exts.extend_from_slice(&build_sni_ext(host));
        }
        for (ext_type, data) in extra_exts {
            exts.extend_from_slice(&ext_type.to_be_bytes());
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(data);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header.
        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let hs_len = body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&body);

        // Record header (legacy 0x0301 outer version).
        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn full_hello_parses() {
        let ciphers = vec![0x1301, 0x1302, 0xc02b];
        let extras = vec![(0x000b, vec![0x01]), (0x0010, vec![0x02, 0x03])];
        let hello = build_hello(0x0303, Some(b"example.com"), &ciphers, &extras);
        let summary = parse(&hello).expect("valid hello parses");
        assert_eq!(summary.version, Some(0x0303));
        assert_eq!(summary.sni.as_deref(), Some("example.com"));
        assert_eq!(summary.cipher_suites, ciphers);
        assert_eq!(
            summary.extension_types,
            vec![EXTENSION_SERVER_NAME, 0x000b, 0x0010]
        );
        assert!(!summary.truncated);
    }

    #[test]
    fn hello_without_sni_has_no_sni() {
        let ciphers = vec![0x1301];
        let extras = vec![(0x000b, vec![0x00])];
        let hello = build_hello(0x0303, None, &ciphers, &extras);
        let summary = parse(&hello).expect("hello without SNI parses");
        assert_eq!(summary.sni, None);
        assert_eq!(summary.extension_types, vec![0x000b]);
        assert!(!summary.truncated);
    }

    #[test]
    fn record_claiming_more_bytes_marks_truncated() {
        let hello = build_hello(0x0303, Some(b"example.com"), &[0x1301], &[]);
        let mut inflated = hello.clone();
        // Bump the record length by 100 without adding bytes.
        let claimed = u16::from_be_bytes([inflated[3], inflated[4]]) + 100;
        inflated[3] = (claimed >> 8) as u8;
        inflated[4] = claimed as u8;
        let summary = parse(&inflated).expect("partial hello still returns Some");
        assert!(summary.truncated);
        assert_eq!(summary.version, Some(0x0303));
    }

    #[test]
    fn application_data_record_returns_none() {
        let mut hello = build_hello(0x0303, Some(b"example.com"), &[0x1301], &[]);
        hello[0] = 0x17;
        assert_eq!(parse(&hello), None);
    }

    #[test]
    fn tiny_garbage_returns_none() {
        assert_eq!(parse(&[0x16, 0x03, 0x01]), None);
    }

    #[test]
    fn cipher_list_capping() {
        let forty: Vec<u16> = (0..40).map(|i| 0x1000 + i).collect();
        let hello40 = build_hello(0x0303, None, &forty, &[]);
        let summary40 = parse(&hello40).expect("40-cipher hello parses");
        assert_eq!(summary40.cipher_suites.len(), 40);
        assert_eq!(summary40.cipher_suites, forty);

        let hundred: Vec<u16> = (0..100).map(|i| 0x2000 + i).collect();
        let hello100 = build_hello(0x0303, None, &hundred, &[]);
        let summary100 = parse(&hello100).expect("100-cipher hello parses");
        assert_eq!(summary100.cipher_suites.len(), MAX_CIPHER_SUITES);
        assert_eq!(summary100.cipher_suites, &hundred[..MAX_CIPHER_SUITES]);
    }

    #[test]
    fn long_sni_is_capped() {
        let long_host = vec![b'a'; 300];
        let hello = build_hello(0x0303, Some(&long_host), &[0x1301], &[]);
        let summary = parse(&hello).expect("long-SNI hello parses");
        let sni = summary.sni.expect("sni present");
        assert_eq!(sni.chars().count(), MAX_SNI_CHARS);
        assert_eq!(sni.len(), MAX_SNI_CHARS);
    }
}
