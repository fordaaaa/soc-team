//! Link-layer parsing: Ethernet header plus 802.1Q decapsulation.

use pnet_packet::ethernet::{EtherType, EtherTypes, EthernetPacket};

use super::l3;
use super::{FrameInfo, L2Info};

/// Maximum number of stacked VLAN tags to strip.
const MAX_VLAN_TAGS: usize = 2;
/// Ethernet header length in bytes.
const ETHERNET_HEADER_LEN: usize = 14;
/// 802.1Q tag length in bytes.
const VLAN_TAG_LEN: usize = 4;

/// Returns true for EtherTypes that introduce an 802.1Q tag.
fn is_vlan(ethertype: EtherType) -> bool {
    ethertype == EtherTypes::Vlan
        || ethertype == EtherTypes::PBridge
        || ethertype.0 == 0x8100
        || ethertype.0 == 0x88A8
}

/// Parse one captured Ethernet frame into a layered summary.
///
/// Returns `None` only when the frame is shorter than 14 bytes (not even
/// an Ethernet header). Truncated or non-IP payloads degrade to `None` at
/// the affected layer, never to an error or panic.
pub fn parse(frame: &[u8]) -> Option<FrameInfo> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let eth = EthernetPacket::new(frame)?;
    let src = eth.get_source();
    let dst = eth.get_destination();
    let mut ethertype = eth.get_ethertype();
    let mut offset = ETHERNET_HEADER_LEN;
    let mut vlan: Option<u16> = None;

    for _ in 0..MAX_VLAN_TAGS {
        if !is_vlan(ethertype) {
            break;
        }
        let tag = match frame.get(offset..offset + VLAN_TAG_LEN) {
            Some(tag) => tag,
            None => break,
        };
        let tci = u16::from_be_bytes([tag[0], tag[1]]);
        if vlan.is_none() {
            vlan = Some(tci & 0x0FFF);
        }
        ethertype = EtherType::new(u16::from_be_bytes([tag[2], tag[3]]));
        offset += VLAN_TAG_LEN;
    }

    let payload: &[u8] = match frame.get(offset..) {
        Some(payload) => payload,
        None => &[],
    };
    let (l3, l4) = l3::parse(payload, ethertype);
    Some(FrameInfo {
        l2: L2Info {
            src,
            dst,
            ethertype,
            vlan,
        },
        l3,
        l4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::MacAddr;
    use pnet_packet::MutablePacket;
    use pnet_packet::ethernet::MutableEthernetPacket;
    use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet_packet::ipv4::MutableIpv4Packet;
    use pnet_packet::ipv6::MutableIpv6Packet;
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
    use pnet_packet::udp::MutableUdpPacket;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn mac(byte: u8) -> MacAddr {
        MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, byte)
    }

    /// Build a UDP segment with a 4-byte payload.
    fn udp_segment(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 12];
        {
            let mut udp = MutableUdpPacket::new(&mut buf).expect("udp buffer too small");
            udp.set_source(src_port);
            udp.set_destination(dst_port);
            udp.set_length(12);
            udp.set_payload(&[1, 2, 3, 4]);
        }
        buf
    }

    /// Build a minimal TCP segment (20-byte header, no options).
    fn tcp_segment(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        {
            let mut tcp = MutableTcpPacket::new(&mut buf).expect("tcp buffer too small");
            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_sequence(0);
            tcp.set_acknowledgement(0);
            tcp.set_data_offset(5);
            tcp.set_flags(flags);
            tcp.set_window(64240);
        }
        buf
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
    fn plain_ipv4_udp_parses_ports() {
        let udp = udp_segment(1234, 53);
        let ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);

        let info = parse(&frame).expect("frame should parse");
        assert_eq!(info.l2.vlan, None);
        assert_eq!(info.l2.ethertype, EtherTypes::Ipv4);
        let l3 = info.l3.expect("l3 should be present");
        assert_eq!(l3.proto, 17);
        assert_eq!(l3.src, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(l3.dst, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)));
        let l4 = info.l4.expect("l4 should be present");
        assert_eq!(l4.src_port, 1234);
        assert_eq!(l4.dst_port, 53);
        assert_eq!(l4.tcp_flags, None);
    }

    #[test]
    fn single_vlan_tag_records_vid() {
        let udp = udp_segment(1234, 53);
        let ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = vlan_frame(&[(EtherTypes::Vlan, 42)], EtherTypes::Ipv4, &ip);

        let info = parse(&frame).expect("frame should parse");
        assert_eq!(info.l2.vlan, Some(42));
        assert_eq!(info.l2.ethertype, EtherTypes::Ipv4);
        assert_eq!(info.l2.src, mac(0x02));
        assert_eq!(info.l2.dst, mac(0x01));
        let l4 = info.l4.expect("l4 should be present");
        assert_eq!(l4.src_port, 1234);
        assert_eq!(l4.dst_port, 53);
    }

    #[test]
    fn double_tagged_records_outer_vid() {
        let udp = udp_segment(9999, 80);
        let ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = vlan_frame(
            &[(EtherType::new(0x88A8), 100), (EtherTypes::Vlan, 200)],
            EtherTypes::Ipv4,
            &ip,
        );

        let info = parse(&frame).expect("frame should parse");
        assert_eq!(info.l2.vlan, Some(100));
        assert_eq!(info.l2.ethertype, EtherTypes::Ipv4);
        let l4 = info.l4.expect("l4 should be present");
        assert_eq!(l4.src_port, 9999);
        assert_eq!(l4.dst_port, 80);
    }

    #[test]
    fn ipv6_udp_parses_v6_addrs() {
        let udp = udp_segment(1234, 53);
        let ip = ipv6_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = eth_frame(EtherTypes::Ipv6, &ip);

        let info = parse(&frame).expect("frame should parse");
        let l3 = info.l3.expect("l3 should be present");
        assert!(matches!(l3.src, IpAddr::V6(_)));
        assert!(matches!(l3.dst, IpAddr::V6(_)));
        assert_eq!(l3.proto, 17);
        let l4 = info.l4.expect("l4 should be present");
        assert_eq!(l4.src_port, 1234);
        assert_eq!(l4.dst_port, 53);
        assert_eq!(l4.tcp_flags, None);
    }

    #[test]
    fn ipv4_tcp_syn_ack_flags() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        assert_eq!(flags, 0x12);
        let tcp = tcp_segment(4433, 80, flags);
        let ip = ipv4_packet(IpNextHeaderProtocols::Tcp, &tcp);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);

        let info = parse(&frame).expect("frame should parse");
        let l3 = info.l3.expect("l3 should be present");
        assert_eq!(l3.proto, 6);
        let l4 = info.l4.expect("l4 should be present");
        assert_eq!(l4.src_port, 4433);
        assert_eq!(l4.dst_port, 80);
        assert_eq!(l4.tcp_flags, Some(0x12));
    }

    #[test]
    fn truncated_ipv4_degrades_to_l2_only() {
        let udp = udp_segment(1234, 53);
        let ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        let truncated = &frame[..14 + 10];

        let info = parse(truncated).expect("l2 should still parse");
        assert_eq!(info.l2.ethertype, EtherTypes::Ipv4);
        assert!(info.l3.is_none());
        assert!(info.l4.is_none());
    }

    #[test]
    fn arp_has_no_l3() {
        let frame = arp_frame();
        let info = parse(&frame).expect("frame should parse");
        assert_eq!(info.l2.ethertype, EtherTypes::Arp);
        assert!(info.l3.is_none());
        assert!(info.l4.is_none());
    }

    #[test]
    fn short_frame_returns_none() {
        assert!(parse(&[0u8; 13]).is_none());
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn oversized_total_length_clamps_gracefully() {
        let udp = udp_segment(1234, 53);
        let mut ip = ipv4_packet(IpNextHeaderProtocols::Udp, &udp);
        // Declare a total length far beyond the actual buffer.
        let declared = (ip.len() + 100) as u16;
        ip[2] = (declared >> 8) as u8;
        ip[3] = (declared & 0xFF) as u8;
        let frame = eth_frame(EtherTypes::Ipv4, &ip);

        let info = parse(&frame).expect("frame should parse");
        assert!(info.l3.is_some());
        let l4 = info.l4.expect("l4 should parse from available bytes");
        assert_eq!(l4.src_port, 1234);
        assert_eq!(l4.dst_port, 53);
    }
}
