//! Direction-normalized flow identity derived from parsed frames.

use std::net::IpAddr;

/// One flow endpoint; `port` is `None` for protocols without ports (ICMP etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    /// IP address of this endpoint.
    pub ip: IpAddr,
    /// Transport port, or `None` when the protocol has no ports or L4 was truncated.
    pub port: Option<u16>,
}

/// Direction-normalized flow identity: `a` is always the lesser endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// IP protocol / next-header number (e.g. 1 ICMP, 6 TCP, 17 UDP).
    pub proto: u8,
    /// Lesser endpoint (`a <= b`).
    pub a: Endpoint,
    /// Greater endpoint (`a <= b`).
    pub b: Endpoint,
}

impl FlowKey {
    /// Build a normalized key from two endpoints, ordering them so `a <= b`.
    ///
    /// Ordering comes from the derived `Ord` on [`Endpoint`]
    /// (`IpAddr` orders V4 < V6, `port` orders `None` < `Some`).
    pub fn new(proto: u8, x: Endpoint, y: Endpoint) -> Self {
        if x <= y {
            Self { proto, a: x, b: y }
        } else {
            Self { proto, a: y, b: x }
        }
    }

    /// Derive a flow key from a parsed frame.
    ///
    /// Returns `None` when `info.l3` is `None` (not a flow: non-IP,
    /// truncated, or link-layer only). Endpoints take IPs from L3 and ports
    /// from `info.l4` (source/destination ports mapped by direction).
    ///
    /// NOTE: fragments/L4-truncated packets key with port `None` — a
    /// documented simplification.
    pub fn from_frame(info: &crate::proto::FrameInfo) -> Option<Self> {
        let l3 = info.l3?;
        let (src_port, dst_port) = match info.l4 {
            Some(l4) => (Some(l4.src_port), Some(l4.dst_port)),
            None => (None, None),
        };
        // NOTE: fragments/l4-truncated packets key with port None — a
        // documented simplification.
        let x = Endpoint {
            ip: l3.src,
            port: src_port,
        };
        let y = Endpoint {
            ip: l3.dst,
            port: dst_port,
        };
        Some(Self::new(l3.proto, x, y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn new_is_symmetric() {
        let x = Endpoint {
            ip: v4(10, 0, 0, 1),
            port: Some(1234),
        };
        let y = Endpoint {
            ip: v4(10, 0, 0, 2),
            port: Some(80),
        };
        assert_eq!(FlowKey::new(6, x, y), FlowKey::new(6, y, x));
    }

    #[test]
    fn ports_differ_means_different_keys() {
        let x = Endpoint {
            ip: v4(10, 0, 0, 1),
            port: Some(1234),
        };
        let y = Endpoint {
            ip: v4(10, 0, 0, 2),
            port: Some(80),
        };
        let y2 = Endpoint {
            ip: v4(10, 0, 0, 2),
            port: Some(81),
        };
        assert_ne!(FlowKey::new(6, x, y), FlowKey::new(6, x, y2));
    }

    #[test]
    fn same_addrs_different_proto_means_different_keys() {
        let x = Endpoint {
            ip: v4(10, 0, 0, 1),
            port: Some(1234),
        };
        let y = Endpoint {
            ip: v4(10, 0, 0, 2),
            port: Some(80),
        };
        assert_ne!(FlowKey::new(6, x, y), FlowKey::new(17, x, y));
    }

    #[test]
    fn none_port_orders_before_some() {
        let none_ep = Endpoint {
            ip: v4(10, 0, 0, 1),
            port: None,
        };
        let some_ep = Endpoint {
            ip: v4(10, 0, 0, 1),
            port: Some(0),
        };
        assert!(none_ep < some_ep);
        let key = FlowKey::new(1, some_ep, none_ep);
        assert_eq!(key.a, none_ep);
        assert_eq!(key.b, some_ep);
    }

    #[test]
    fn v4_orders_before_v6() {
        let v4_ep = Endpoint {
            ip: v4(255, 255, 255, 255),
            port: None,
        };
        let v6_ep = Endpoint {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: None,
        };
        assert!(v4_ep < v6_ep);
        let key = FlowKey::new(6, v6_ep, v4_ep);
        assert_eq!(key.a, v4_ep);
    }
}
