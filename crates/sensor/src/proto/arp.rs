//! ARP packet body parsing (RFC 826 Ethernet/IPv4 shape).
//! Never panics: malformed input degrades to `None`.

/// Fixed wire length of the Ethernet/IPv4 ARP body.
const ARP_BODY_LEN: usize = 28;
/// Hardware type for Ethernet.
const HTYPE_ETHERNET: u16 = 1;
/// Protocol type for IPv4.
const PTYPE_IPV4: u16 = 0x0800;
/// ARP operation code for a request.
const OPER_REQUEST: u16 = 1;
/// ARP operation code for a reply.
const OPER_REPLY: u16 = 2;

/// Zeek-inspired summary of one ARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpSummary {
    /// Sender protocol (IPv4) address, dotted quad.
    pub sender_ip: String,
    /// Sender hardware address, colon-separated lowercase hex.
    pub sender_mac: String,
    /// Target protocol (IPv4) address, dotted quad.
    pub target_ip: String,
    /// Target hardware address, colon-separated lowercase hex; None when the packet's target MAC is absent.
    pub target_mac: Option<String>,
    /// True for a reply (operation 2), false for a request (operation 1).
    pub is_reply: bool,
    /// True when sender IP equals target IP (gratuitous ARP).
    pub is_gratuitous: bool,
}

/// Parse an ARP body (the bytes after the Ethernet header). Only the
/// Ethernet/IPv4 shape is accepted: hardware type 1, protocol type
/// 0x0800, hlen 6, plen 4, operation 1 (request) or 2 (reply). Returns
/// None on anything else; never panics.
pub fn parse(body: &[u8]) -> Option<ArpSummary> {
    // Ethernet pads short frames to the 60-byte minimum; only the first
    // 28 bytes are the ARP body.
    let wire = body.get(..ARP_BODY_LEN)?;
    let htype = u16::from_be_bytes([wire[0], wire[1]]);
    let ptype = u16::from_be_bytes([wire[2], wire[3]]);
    let hlen = wire[4];
    let plen = wire[5];
    let oper = u16::from_be_bytes([wire[6], wire[7]]);
    if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return None;
    }
    let is_reply = match oper {
        OPER_REQUEST => false,
        OPER_REPLY => true,
        _ => return None,
    };
    // wire is exactly ARP_BODY_LEN bytes here, so every read is in-bounds.
    let sha: [u8; 6] = wire[8..14].try_into().ok()?;
    let spa: [u8; 4] = wire[14..18].try_into().ok()?;
    let tha: [u8; 6] = wire[18..24].try_into().ok()?;
    let tpa: [u8; 4] = wire[24..28].try_into().ok()?;

    Some(ArpSummary {
        sender_ip: render_ipv4(&spa),
        sender_mac: render_mac(&sha),
        target_ip: render_ipv4(&tpa),
        // tha is always present when the 28 bytes are intact; all-zero
        // (common in gratuitous requests) renders as 00:00:00:00:00:00.
        target_mac: Some(render_mac(&tha)),
        is_reply,
        is_gratuitous: spa == tpa,
    })
}

/// Render a MAC as colon-separated lowercase hex (`aa:bb:cc:dd:ee:ff`).
fn render_mac(mac: &[u8; 6]) -> String {
    let mut out = String::with_capacity(17);
    for (i, byte) in mac.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Render an IPv4 address as dotted-quad decimal.
fn render_ipv4(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03];
    const SENDER_IP: [u8; 4] = [192, 0, 2, 10];
    const TARGET_IP: [u8; 4] = [192, 0, 2, 1];
    const ZERO_MAC: [u8; 6] = [0x00; 6];

    /// Build a well-formed 28-byte ARP body with the given fields.
    fn arp_body(oper: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
        let mut body = Vec::with_capacity(ARP_BODY_LEN);
        body.extend_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        body.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
        body.push(6); // hlen
        body.push(4); // plen
        body.extend_from_slice(&oper.to_be_bytes());
        body.extend_from_slice(&sha);
        body.extend_from_slice(&spa);
        body.extend_from_slice(&tha);
        body.extend_from_slice(&tpa);
        body
    }

    #[test]
    fn parses_request() {
        let body = arp_body(OPER_REQUEST, SENDER_MAC, SENDER_IP, ZERO_MAC, TARGET_IP);
        let summary = parse(&body).expect("request body should parse");
        assert_eq!(summary.sender_ip, "192.0.2.10");
        assert_eq!(summary.sender_mac, "aa:bb:cc:01:02:03");
        assert_eq!(summary.target_ip, "192.0.2.1");
        assert_eq!(summary.target_mac, Some("00:00:00:00:00:00".to_owned()));
        assert!(!summary.is_reply);
        assert!(!summary.is_gratuitous);
    }

    #[test]
    fn parses_reply_with_target_mac() {
        let tha = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        // A reply answers the request: sender/target roles are swapped.
        let body = arp_body(OPER_REPLY, SENDER_MAC, TARGET_IP, tha, SENDER_IP);
        let summary = parse(&body).expect("reply body should parse");
        assert!(summary.is_reply);
        assert_eq!(summary.target_mac, Some("de:ad:be:ef:00:01".to_owned()));
    }

    #[test]
    fn flags_gratuitous_when_spa_equals_tpa() {
        let body = arp_body(OPER_REQUEST, SENDER_MAC, SENDER_IP, ZERO_MAC, SENDER_IP);
        let summary = parse(&body).expect("gratuitous request should parse");
        assert!(summary.is_gratuitous);
    }

    #[test]
    fn rejects_truncated_body() {
        let body = arp_body(OPER_REQUEST, SENDER_MAC, SENDER_IP, ZERO_MAC, TARGET_IP);
        assert_eq!(parse(&body[..27]), None);
        assert_eq!(parse(&body[..14]), None);
        assert_eq!(parse(&[]), None);
    }

    #[test]
    fn rejects_wrong_lengths() {
        let base = arp_body(OPER_REQUEST, SENDER_MAC, SENDER_IP, ZERO_MAC, TARGET_IP);

        let mut hlen8 = base.clone();
        hlen8[4] = 8;
        assert_eq!(parse(&hlen8), None);

        let mut plen6 = base.clone();
        plen6[5] = 6;
        assert_eq!(parse(&plen6), None);

        let mut htype2 = base.clone();
        htype2[1] = 2; // htype 0x0002, not Ethernet
        assert_eq!(parse(&htype2), None);

        let mut ptype_v6 = base.clone();
        ptype_v6[2] = 0x86;
        ptype_v6[3] = 0xdd; // ptype 0x86dd, not IPv4
        assert_eq!(parse(&ptype_v6), None);
    }

    #[test]
    fn rejects_unknown_operation() {
        let body = arp_body(3, SENDER_MAC, SENDER_IP, ZERO_MAC, TARGET_IP);
        assert_eq!(parse(&body), None);
    }
}
