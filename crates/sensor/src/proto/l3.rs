//! Network- and transport-layer parsing over a decapsulated payload.

use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use std::net::IpAddr;

use super::{L3Info, L4Info};

/// Minimum IPv4 header length in bytes.
const IPV4_MIN_HEADER_LEN: usize = 20;
/// IPv6 fixed header length in bytes.
const IPV6_HEADER_LEN: usize = 40;
/// Minimum TCP header length in bytes.
const TCP_MIN_HEADER_LEN: usize = 20;
/// UDP header length in bytes.
const UDP_HEADER_LEN: usize = 8;

/// Parse the network layer (and TCP/UDP ports) from a decapsulated payload.
///
/// `payload` is the bytes after the outermost Ethernet header and any
/// 802.1Q tags; `ethertype` is the innermost EtherType. Returns the L3
/// summary (when the payload is IPv4/IPv6 and well-formed) plus the L4
/// summary (when ports are present and well-formed).
///
/// Never panics: truncated or bogus headers degrade to `(None, None)` at
/// the affected layer. Non-IP EtherTypes (e.g. ARP) return `(None, None)`
/// without indicating malformation.
pub fn parse(payload: &[u8], ethertype: EtherType) -> (Option<L3Info>, Option<L4Info>) {
    if ethertype == EtherTypes::Ipv4 {
        parse_ipv4(payload)
    } else if ethertype == EtherTypes::Ipv6 {
        parse_ipv6(payload)
    } else {
        (None, None)
    }
}

/// Parse an IPv4 packet and its TCP/UDP transport header.
fn parse_ipv4(payload: &[u8]) -> (Option<L3Info>, Option<L4Info>) {
    let packet = match Ipv4Packet::new(payload) {
        Some(packet) => packet,
        None => return (None, None),
    };
    let header_len = packet.get_header_length() as usize * 4;
    if header_len < IPV4_MIN_HEADER_LEN || header_len > payload.len() {
        return (None, None);
    }
    let total_len = packet.get_total_length() as usize;
    let backing = &payload[header_len..];
    let wanted = total_len.saturating_sub(header_len);
    let transport = if wanted < backing.len() {
        &backing[..wanted]
    } else {
        backing
    };
    let l3 = L3Info {
        src: IpAddr::V4(packet.get_source()),
        dst: IpAddr::V4(packet.get_destination()),
        proto: packet.get_next_level_protocol().0,
    };
    let l4 = parse_transport(l3.proto, transport);
    (Some(l3), l4)
}

/// Parse an IPv6 packet and its TCP/UDP transport header.
///
/// Extension headers are ignored for now: the fixed-header next-header
/// value is treated as the final transport protocol.
fn parse_ipv6(payload: &[u8]) -> (Option<L3Info>, Option<L4Info>) {
    let packet = match Ipv6Packet::new(payload) {
        Some(packet) => packet,
        None => return (None, None),
    };
    if payload.len() < IPV6_HEADER_LEN {
        return (None, None);
    }
    let transport = &payload[IPV6_HEADER_LEN..];
    let l3 = L3Info {
        src: IpAddr::V6(packet.get_source()),
        dst: IpAddr::V6(packet.get_destination()),
        proto: packet.get_next_header().0,
    };
    let l4 = parse_transport(l3.proto, transport);
    (Some(l3), l4)
}

/// Parse TCP/UDP ports and TCP flags from a transport slice.
///
/// Returns `None` for non-port protocols (e.g. ICMP) or when the slice is
/// shorter than the transport header.
fn parse_transport(proto: u8, transport: &[u8]) -> Option<L4Info> {
    if proto == IpNextHeaderProtocols::Tcp.0 {
        if transport.len() < TCP_MIN_HEADER_LEN {
            return None;
        }
        let tcp = TcpPacket::new(transport)?;
        Some(L4Info {
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
            tcp_flags: Some(tcp.get_flags()),
        })
    } else if proto == IpNextHeaderProtocols::Udp.0 {
        if transport.len() < UDP_HEADER_LEN {
            return None;
        }
        let udp = UdpPacket::new(transport)?;
        Some(L4Info {
            src_port: udp.get_source(),
            dst_port: udp.get_destination(),
            tcp_flags: None,
        })
    } else {
        None
    }
}
