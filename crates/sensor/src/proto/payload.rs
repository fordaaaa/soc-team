//! L4 payload extraction: the TCP/UDP payload bytes behind a frame.
//!
//! Walks Ethernet (+≤2 VLAN tags) → IPv4 (ihl) or IPv6 (fixed 40) →
//! TCP (data_offset) or UDP (8). Honors the IPv4 total_length clamp:
//! payload never extends past the IP-declared end even when the captured
//! frame is longer. Clamps naturally to captured bytes under snaplen.
//!
//! NOTE: this duplicates the offset walk in l2/l3 by design — one extra
//! bounded pass, to be folded into FrameInfo only if the 1F benches
//! demand it.
//!
//! Returns None for non-IP, non-TCP/UDP, or truncated headers. An empty
//! payload (e.g. bare SYN) is Some(&[]).

/// Maximum number of stacked VLAN tags to strip (matches l2.rs).
const MAX_VLAN_TAGS: usize = 2;
/// Ethernet header length in bytes.
const ETHERNET_HEADER_LEN: usize = 14;
/// Offset of the EtherType field in the Ethernet header.
const ETHERTYPE_OFFSET: usize = 12;
/// 802.1Q tag length in bytes.
const VLAN_TAG_LEN: usize = 4;
/// Offset of the inner EtherType within a VLAN tag.
const VLAN_INNER_ETHERTYPE_OFFSET: usize = 2;
/// 802.1Q VLAN EtherType.
const ETHERTYPE_VLAN: u16 = 0x8100;
/// 802.1ad (QinQ) EtherType, treated as a VLAN tag like l2.rs.
const ETHERTYPE_QINQ: u16 = 0x88A8;
/// IPv4 EtherType.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv6 EtherType.
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Minimum IPv4 header length in bytes.
const IPV4_MIN_HEADER_LEN: usize = 20;
/// Minimum sane IPv4 IHL (in 32-bit words).
const IPV4_MIN_IHL: u8 = 5;
/// Mask for the IHL nibble of the first IPv4 byte.
const IPV4_IHL_MASK: u8 = 0x0F;
/// Expected IPv4 version nibble.
const IPV4_VERSION: u8 = 4;
/// Offset of total_length within the IPv4 header.
const IPV4_TOTAL_LENGTH_OFFSET: usize = 2;
/// Offset of the protocol byte within the IPv4 header.
const IPV4_PROTO_OFFSET: usize = 9;
/// IPv6 fixed header length in bytes.
const IPV6_HEADER_LEN: usize = 40;
/// Offset of payload_length within the IPv6 header.
const IPV6_PAYLOAD_LENGTH_OFFSET: usize = 4;
/// Offset of the next-header byte within the IPv6 header.
const IPV6_NEXT_HEADER_OFFSET: usize = 6;
/// Minimum TCP header length in bytes.
const TCP_MIN_HEADER_LEN: usize = 20;
/// Minimum sane TCP data offset (in 32-bit words).
const TCP_MIN_DATA_OFFSET: u8 = 5;
/// Offset of the data-offset byte within the TCP header.
const TCP_DATA_OFFSET_BYTE: usize = 12;
/// UDP header length in bytes.
const UDP_HEADER_LEN: usize = 8;
/// TCP protocol number.
const PROTO_TCP: u8 = 6;
/// UDP protocol number.
const PROTO_UDP: u8 = 17;

/// Extract the TCP/UDP payload slice of an Ethernet frame. Never panics.
pub fn l4_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([
        *frame.get(ETHERTYPE_OFFSET)?,
        *frame.get(ETHERTYPE_OFFSET + 1)?,
    ]);
    let mut offset = ETHERNET_HEADER_LEN;

    for _ in 0..MAX_VLAN_TAGS {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        let tag = frame.get(offset..offset + VLAN_TAG_LEN)?;
        ethertype = u16::from_be_bytes([
            tag[VLAN_INNER_ETHERTYPE_OFFSET],
            tag[VLAN_INNER_ETHERTYPE_OFFSET + 1],
        ]);
        offset += VLAN_TAG_LEN;
    }

    if ethertype == ETHERTYPE_IPV4 {
        ipv4_payload(frame, offset)
    } else if ethertype == ETHERTYPE_IPV6 {
        ipv6_payload(frame, offset)
    } else {
        None
    }
}

/// IPv4 leg: ihl-sized header, total_length clamp, then TCP/UDP tail.
fn ipv4_payload(frame: &[u8], ip_start: usize) -> Option<&[u8]> {
    let first = *frame.get(ip_start)?;
    if first >> 4 != IPV4_VERSION {
        return None;
    }
    let ihl = first & IPV4_IHL_MASK;
    if ihl < IPV4_MIN_IHL {
        return None;
    }
    let header_len = (ihl as usize) * 4;
    if header_len < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let total_length = u16::from_be_bytes([
        *frame.get(ip_start.checked_add(IPV4_TOTAL_LENGTH_OFFSET)?)?,
        *frame.get(ip_start.checked_add(IPV4_TOTAL_LENGTH_OFFSET + 1)?)?,
    ]) as usize;
    let proto = *frame.get(ip_start.checked_add(IPV4_PROTO_OFFSET)?)?;
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let ip_end = ip_start.saturating_add(total_length).min(frame.len());
    let transport_start = ip_start.saturating_add(header_len);
    transport_payload(frame, proto, transport_start, ip_end)
}

/// IPv6 leg: fixed 40-byte header, payload_length clamp, then TCP/UDP tail.
///
/// Extension headers are a documented simplification (same as l3.rs): the
/// fixed-header next-header value is treated as the final transport protocol.
fn ipv6_payload(frame: &[u8], ip_start: usize) -> Option<&[u8]> {
    let next_header = *frame.get(ip_start.checked_add(IPV6_NEXT_HEADER_OFFSET)?)?;
    if next_header != PROTO_TCP && next_header != PROTO_UDP {
        return None;
    }
    let payload_length = u16::from_be_bytes([
        *frame.get(ip_start.checked_add(IPV6_PAYLOAD_LENGTH_OFFSET)?)?,
        *frame.get(ip_start.checked_add(IPV6_PAYLOAD_LENGTH_OFFSET + 1)?)?,
    ]) as usize;
    let transport_start = ip_start.saturating_add(IPV6_HEADER_LEN);
    let declared_end = transport_start.saturating_add(payload_length);
    let ip_end = declared_end.min(frame.len());
    transport_payload(frame, next_header, transport_start, ip_end)
}

/// Shared TCP/UDP tail: strip the transport header, return bytes to `ip_end`.
fn transport_payload(
    frame: &[u8],
    proto: u8,
    transport_start: usize,
    ip_end: usize,
) -> Option<&[u8]> {
    if transport_start > ip_end || ip_end > frame.len() {
        return None;
    }
    if proto == PROTO_UDP {
        let payload_start = transport_start.checked_add(UDP_HEADER_LEN)?;
        if payload_start > ip_end {
            return None;
        }
        frame.get(payload_start..ip_end)
    } else if proto == PROTO_TCP {
        let min_end = transport_start.checked_add(TCP_MIN_HEADER_LEN)?;
        if min_end > ip_end {
            return None;
        }
        let data_offset = frame.get(transport_start.checked_add(TCP_DATA_OFFSET_BYTE)?)? >> 4;
        if data_offset < TCP_MIN_DATA_OFFSET {
            return None;
        }
        let header_len = (data_offset as usize) * 4;
        let payload_start = transport_start.checked_add(header_len)?;
        if payload_start > ip_end {
            return None;
        }
        frame.get(payload_start..ip_end)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::MacAddr;
    use pnet_packet::MutablePacket;
    use pnet_packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
    use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet_packet::ipv4::MutableIpv4Packet;
    use pnet_packet::ipv6::MutableIpv6Packet;
    use pnet_packet::tcp::MutableTcpPacket;
    use pnet_packet::udp::MutableUdpPacket;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn mac(byte: u8) -> MacAddr {
        MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, byte)
    }

    /// Build a UDP segment with an arbitrary payload.
    fn udp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + payload.len()];
        {
            let mut udp = MutableUdpPacket::new(&mut buf).expect("udp buffer too small");
            udp.set_source(src_port);
            udp.set_destination(dst_port);
            udp.set_length((8 + payload.len()) as u16);
            udp.set_payload(payload);
        }
        buf
    }

    /// Build a TCP segment (data_offset 5) with an arbitrary payload.
    fn tcp_segment(src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + payload.len()];
        {
            let mut tcp = MutableTcpPacket::new(&mut buf).expect("tcp buffer too small");
            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_sequence(0);
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_flags(flags);
            tcp.set_window(64240);
            tcp.set_payload(payload);
        }
        buf
    }

    /// Build a minimal TCP segment (20-byte header, no payload).
    fn tcp_header_only(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        tcp_segment(src_port, dst_port, flags, &[])
    }

    /// Build an IPv4 packet wrapping the given transport bytes.
    fn ipv4_packet(proto: IpNextHeaderProtocol, transport: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + transport.len()];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).expect("ipv4 buffer too small");
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + transport.len()) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(proto);
            ip.set_source(Ipv4Addr::new(192, 168, 0, 1));
            ip.set_destination(Ipv4Addr::new(192, 168, 0, 2));
            ip.set_payload(transport);
        }
        buf
    }

    /// Build an IPv6 packet wrapping the given transport bytes.
    fn ipv6_packet(next_header: IpNextHeaderProtocol, transport: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 40 + transport.len()];
        {
            let mut ip = MutableIpv6Packet::new(&mut buf).expect("ipv6 buffer too small");
            ip.set_version(6);
            ip.set_payload_length(transport.len() as u16);
            ip.set_next_header(next_header);
            ip.set_hop_limit(64);
            ip.set_source(Ipv6Addr::LOCALHOST);
            ip.set_destination(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
            ip.set_payload(transport);
        }
        buf
    }

    /// Build a plain Ethernet frame wrapping the given L3 packet.
    fn eth_frame(ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 14 + payload.len()];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf).expect("eth buffer too small");
            eth.set_destination(mac(0x01));
            eth.set_source(mac(0x02));
            eth.set_ethertype(ethertype);
            eth.set_payload(payload);
        }
        buf
    }

    /// Build an Ethernet frame with stacked VLAN tags.
    ///
    /// `tags` holds `(tag_ethertype, vid)` pairs from outer to inner.
    fn vlan_frame(
        tags: &[(EtherType, u16)],
        inner_ethertype: EtherType,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(14 + tags.len() * 4 + payload.len());
        buf.extend_from_slice(&mac(0x01).octets());
        buf.extend_from_slice(&mac(0x02).octets());
        for (tag_ethertype, vid) in tags {
            buf.extend_from_slice(&tag_ethertype.0.to_be_bytes());
            let tci: u16 = vid & 0x0FFF;
            buf.extend_from_slice(&tci.to_be_bytes());
        }
        buf.extend_from_slice(&inner_ethertype.0.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Build a minimal Ethernet(ARP) frame (28-byte ARP payload).
    fn arp_frame() -> Vec<u8> {
        let mut buf = vec![0u8; 14 + 28];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf).expect("eth buffer too small");
            eth.set_destination(mac(0x01));
            eth.set_source(mac(0x02));
            eth.set_ethertype(EtherTypes::Arp);
            let packet = eth.packet_mut();
            packet[14] = 0x00;
            packet[15] = 0x01;
            packet[16] = 0x08;
            packet[17] = 0x00;
        }
        buf
    }

    #[test]
    fn udp_payload_returned() {
        let want = [10u8, 20, 30, 40, 50, 60, 70, 80];
        let udp = udp_segment(1234, 53, &want);
        let ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        assert_eq!(l4_payload(&frame), Some(want.as_slice()));
    }

    #[test]
    fn tcp_payload_returned() {
        let want = b"hello-tcp-payload";
        let tcp = tcp_segment(4433, 80, 0x18, want);
        let ip = ipv4_packet(IpNextHeaderProtocols::Tcp, &tcp);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        assert_eq!(l4_payload(&frame), Some(want.as_slice()));
    }

    #[test]
    fn bare_syn_is_empty() {
        let tcp = tcp_header_only(1234, 80, 0x02);
        let ip = ipv4_packet(IpNextHeaderProtocols::Tcp, &tcp);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        let got = l4_payload(&frame).expect("bare SYN should yield Some");
        assert_eq!(got, &[] as &[u8]);
    }

    #[test]
    fn vlan_tagged_udp_found() {
        let want = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let udp = udp_segment(1234, 53, &want);
        let ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = vlan_frame(&[(EtherTypes::Vlan, 42)], EtherTypes::Ipv4, &ip);
        assert_eq!(l4_payload(&frame), Some(want.as_slice()));
    }

    #[test]
    fn short_total_length_clamps_trailing_bytes() {
        let want = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let udp = udp_segment(1234, 53, &want);
        let ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        let mut frame = eth_frame(EtherTypes::Ipv4, &ip);
        // Captured frame is longer than the IP-declared length (trailer).
        frame.extend_from_slice(&[0xAA; 16]);
        let got = l4_payload(&frame).expect("payload should be found");
        assert_eq!(got, want.as_slice());
    }

    #[test]
    fn truncated_tcp_header_is_none() {
        // Only 10 bytes of transport: less than the 20-byte TCP minimum.
        let truncated = [0u8; 10];
        let ip = ipv4_packet(IpNextHeaderProtocols::Tcp, &truncated);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        assert_eq!(l4_payload(&frame), None);
    }

    #[test]
    fn arp_is_none() {
        let frame = arp_frame();
        assert_eq!(l4_payload(&frame), None);
    }

    #[test]
    fn non_tcp_udp_proto_is_none() {
        let icmp_payload = [8u8, 0, 0, 0, 0, 0, 0, 0];
        let ip = ipv4_packet(IpNextHeaderProtocols::Icmp, &icmp_payload);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        assert_eq!(l4_payload(&frame), None);
    }

    #[test]
    fn ipv6_udp_payload_returned() {
        let want = [11u8, 22, 33, 44, 55, 66, 77, 88];
        let udp = udp_segment(1234, 53, &want);
        let ip = ipv6_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = eth_frame(EtherTypes::Ipv6, &ip);
        assert_eq!(l4_payload(&frame), Some(want.as_slice()));
    }
}
