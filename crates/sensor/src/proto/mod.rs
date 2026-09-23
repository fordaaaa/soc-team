//! Pure protocol parsing for the sensor pipeline — bytes in, typed summaries out, no I/O.

use pnet::datalink::MacAddr;
use pnet_packet::ethernet::EtherType;
use std::net::IpAddr;

pub mod l2;
pub mod l3;

/// Link-layer identity of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Info {
    /// Source MAC address from the outer Ethernet header.
    pub src: MacAddr,
    /// Destination MAC address from the outer Ethernet header.
    pub dst: MacAddr,
    /// Innermost EtherType (after VLAN decapsulation).
    pub ethertype: EtherType,
    /// First 802.1Q VLAN id; None when untagged.
    pub vlan: Option<u16>,
}

/// Network-layer identity of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3Info {
    /// Source IP address.
    pub src: IpAddr,
    /// Destination IP address.
    pub dst: IpAddr,
    /// IP protocol / next-header number (e.g. 1 ICMP, 6 TCP, 17 UDP, 58 ICMPv6).
    pub proto: u8,
}

/// Transport-layer identity of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L4Info {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Raw TCP flags byte; None for UDP.
    pub tcp_flags: Option<u8>,
}

/// Layered summary of one captured frame. Absent layers mean "not present
/// or truncated" — never an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameInfo {
    /// Link-layer info; always present when [`crate::proto::l2::parse`] returns `Some`.
    pub l2: L2Info,
    /// Network-layer info; `None` when absent, non-IP, or truncated.
    pub l3: Option<L3Info>,
    /// Transport-layer info; `None` when absent, non-TCP/UDP, or truncated.
    pub l4: Option<L4Info>,
}
