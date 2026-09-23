//! Flow table: fold parsed frames into bidirectional records with timeout expiry.

use super::{FlowKey, key::Endpoint};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Why a flow record left the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// No packet seen for at least the idle timeout.
    IdleTimeout,
    /// Span from first packet reached the active timeout (flow split).
    ActiveTimeout,
    /// A TCP FIN was observed (first FIN closes; half-close is not tracked).
    Fin,
    /// A TCP RST was observed.
    Rst,
    /// Table was drained explicitly via [`FlowTable::finish`].
    Eof,
}

/// An expired, immutable flow record emitted by [`FlowTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    /// Direction-normalized flow identity.
    pub key: FlowKey,
    /// Timestamp of the first packet in this record's span.
    pub first: SystemTime,
    /// Timestamp of the last packet in this record's span.
    pub last: SystemTime,
    /// Packet count in the `a → b` direction.
    pub packets_a_to_b: u64,
    /// Byte count (sum of observed `frame_len`) in the `a → b` direction.
    pub bytes_a_to_b: u64,
    /// Packet count in the `b → a` direction.
    pub packets_b_to_a: u64,
    /// Byte count (sum of observed `frame_len`) in the `b → a` direction.
    pub bytes_b_to_a: u64,
    /// A TCP SYN was observed at least once.
    pub syn: bool,
    /// A TCP FIN was observed at least once.
    pub fin: bool,
    /// A TCP RST was observed at least once.
    pub rst: bool,
    /// Why this record was emitted.
    pub end: EndReason,
}

/// Private mutable accumulator for one live flow; same fields as
/// [`FlowRecord`] minus `end`.
struct FlowEntry {
    key: FlowKey,
    first: SystemTime,
    last: SystemTime,
    packets_a_to_b: u64,
    bytes_a_to_b: u64,
    packets_b_to_a: u64,
    bytes_b_to_a: u64,
    syn: bool,
    fin: bool,
    rst: bool,
}

/// Bidirectional flow table with idle/active timeout expiry.
///
/// Time is injected by the caller (`ts` / `now` parameters); this type
/// performs no I/O, spawns no threads, and never reads a clock.
pub struct FlowTable {
    /// Emit idle when `now - last >= idle_timeout`.
    idle_timeout: Duration,
    /// Emit active-split when `now - first >= active_timeout`.
    active_timeout: Duration,
    /// Live flows by normalized key.
    flows: HashMap<FlowKey, FlowEntry>,
}

impl FlowTable {
    /// Create an empty table.
    ///
    /// Typical values (Zeek-inspired): idle 60s, active 3600s.
    pub fn new(idle_timeout: Duration, active_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            active_timeout,
            flows: HashMap::new(),
        }
    }

    /// Fold one parsed frame into the table.
    ///
    /// Frames without L3 (`None` key) are ignored. Direction is decided by
    /// comparing the packet's actual `(src ip, src port)` against `key.a`:
    /// a match counts toward `a → b`, anything else toward `b → a`. TCP
    /// flags (`0x02` SYN, `0x01` FIN, `0x04` RST) set sticky booleans that
    /// are never cleared.
    pub fn observe(&mut self, ts: SystemTime, frame_len: u64, info: &crate::proto::FrameInfo) {
        let Some(key) = FlowKey::from_frame(info) else {
            return;
        };
        let Some(l3) = info.l3 else {
            return;
        };
        let src_port = info.l4.map(|l4| l4.src_port);
        let src_ep = Endpoint {
            ip: l3.src,
            port: src_port,
        };
        let is_a_to_b = src_ep == key.a;

        let (syn, fin, rst) = match info.l4.and_then(|l4| l4.tcp_flags) {
            Some(flags) => (flags & 0x02 != 0, flags & 0x01 != 0, flags & 0x04 != 0),
            None => (false, false, false),
        };

        match self.flows.get_mut(&key) {
            Some(entry) => {
                if ts > entry.last {
                    entry.last = ts;
                }
                if is_a_to_b {
                    entry.packets_a_to_b += 1;
                    entry.bytes_a_to_b += frame_len;
                } else {
                    entry.packets_b_to_a += 1;
                    entry.bytes_b_to_a += frame_len;
                }
                entry.syn |= syn;
                entry.fin |= fin;
                entry.rst |= rst;
            }
            None => {
                let (packets_a_to_b, bytes_a_to_b, packets_b_to_a, bytes_b_to_a) = if is_a_to_b {
                    (1, frame_len, 0, 0)
                } else {
                    (0, 0, 1, frame_len)
                };
                self.flows.insert(
                    key.clone(),
                    FlowEntry {
                        key,
                        first: ts,
                        last: ts,
                        packets_a_to_b,
                        bytes_a_to_b,
                        packets_b_to_a,
                        bytes_b_to_a,
                        syn,
                        fin,
                        rst,
                    },
                );
            }
        }
    }

    /// Reap expired flows and return their records.
    ///
    /// An entry is reaped when a TCP RST or FIN was seen, when
    /// `now - last >= idle_timeout`, or when `now - first >=
    /// active_timeout`. When several apply, precedence is
    /// `Rst > Fin > IdleTimeout > ActiveTimeout`.
    ///
    /// Reaping the first FIN is a documented simplification: we do not
    /// track both directions' FINs (no half-close tracking). Active-timeout
    /// expiry is a flow split: later packets start a fresh entry.
    pub fn expire(&mut self, now: SystemTime) -> Vec<FlowRecord> {
        let mut dead: Vec<FlowKey> = Vec::new();
        let mut reasons: Vec<EndReason> = Vec::new();
        for (key, entry) in &self.flows {
            let idle_expired = now
                .duration_since(entry.last)
                .map(|d| d >= self.idle_timeout)
                .unwrap_or(false);
            let active_expired = now
                .duration_since(entry.first)
                .map(|d| d >= self.active_timeout)
                .unwrap_or(false);
            let reason = if entry.rst {
                Some(EndReason::Rst)
            } else if entry.fin {
                Some(EndReason::Fin)
            } else if idle_expired {
                Some(EndReason::IdleTimeout)
            } else if active_expired {
                Some(EndReason::ActiveTimeout)
            } else {
                None
            };
            if let Some(reason) = reason {
                dead.push(key.clone());
                reasons.push(reason);
            }
        }
        let mut out = Vec::with_capacity(dead.len());
        for (key, end) in dead.into_iter().zip(reasons) {
            if let Some(entry) = self.flows.remove(&key) {
                out.push(FlowRecord {
                    key: entry.key,
                    first: entry.first,
                    last: entry.last,
                    packets_a_to_b: entry.packets_a_to_b,
                    bytes_a_to_b: entry.bytes_a_to_b,
                    packets_b_to_a: entry.packets_b_to_a,
                    bytes_b_to_a: entry.bytes_b_to_a,
                    syn: entry.syn,
                    fin: entry.fin,
                    rst: entry.rst,
                    end,
                });
            }
        }
        out
    }

    /// Drain every live flow with [`EndReason::Eof`].
    pub fn finish(self) -> Vec<FlowRecord> {
        self.flows
            .into_values()
            .map(|entry| FlowRecord {
                key: entry.key,
                first: entry.first,
                last: entry.last,
                packets_a_to_b: entry.packets_a_to_b,
                bytes_a_to_b: entry.bytes_a_to_b,
                packets_b_to_a: entry.packets_b_to_a,
                bytes_b_to_a: entry.bytes_b_to_a,
                syn: entry.syn,
                fin: entry.fin,
                rst: entry.rst,
                end: EndReason::Eof,
            })
            .collect()
    }

    /// Number of live flows currently in the table.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// True when no live flows are in the table.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
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
    use pnet_packet::tcp::MutableTcpPacket;
    use pnet_packet::udp::MutableUdpPacket;
    use std::net::Ipv4Addr;
    use std::time::UNIX_EPOCH;

    fn ts(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

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
    fn ipv4_packet_with(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: IpNextHeaderProtocol,
        transport: &[u8],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + transport.len()];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).expect("ipv4 buffer too small");
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + transport.len()) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(proto);
            ip.set_source(src);
            ip.set_destination(dst);
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

    fn parse_info(frame: &[u8]) -> crate::proto::FrameInfo {
        crate::proto::l2::parse(frame).expect("frame should parse")
    }

    fn tcp_frame(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let seg = tcp_segment(sport, dport, flags);
        let ip = ipv4_packet_with(src, dst, IpNextHeaderProtocols::Tcp, &seg);
        eth_frame(EtherTypes::Ipv4, &ip)
    }

    #[test]
    fn bidirectional_folding() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        let fwd = tcp_frame(x, y, 1234, 80, 0x10);
        let rev = tcp_frame(y, x, 80, 1234, 0x10);
        let fwd_len = fwd.len() as u64;
        let rev_len = rev.len() as u64;

        table.observe(ts(0), fwd_len, &parse_info(&fwd));
        table.observe(ts(1), fwd_len, &parse_info(&fwd));
        table.observe(ts(2), rev_len, &parse_info(&rev));
        assert_eq!(table.len(), 1);

        let records = table.finish();
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.packets_a_to_b, 2);
        assert_eq!(rec.packets_b_to_a, 1);
        assert_eq!(rec.bytes_a_to_b, 2 * fwd_len);
        assert_eq!(rec.bytes_b_to_a, rev_len);
    }

    #[test]
    fn idle_expiry() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        let frame = tcp_frame(x, y, 1234, 80, 0x10);
        let len = frame.len() as u64;
        table.observe(ts(0), len, &parse_info(&frame));

        let early = table.expire(ts(59));
        assert!(early.is_empty());
        assert_eq!(table.len(), 1);

        let late = table.expire(ts(61));
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].end, EndReason::IdleTimeout);
        assert!(table.is_empty());
    }

    #[test]
    fn active_split() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(5));
        let frame = tcp_frame(x, y, 1234, 80, 0x10);
        let len = frame.len() as u64;
        for t in 0..=5u64 {
            table.observe(ts(t), len, &parse_info(&frame));
        }
        let expired = table.expire(ts(5));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].end, EndReason::ActiveTimeout);
        assert_eq!(expired[0].packets_a_to_b + expired[0].packets_b_to_a, 6);
        assert!(table.is_empty());

        table.observe(ts(6), len, &parse_info(&frame));
        assert_eq!(table.len(), 1);
        for t in 7..=10u64 {
            table.observe(ts(t), len, &parse_info(&frame));
        }
        let rest = table.finish();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].first, ts(6));
        assert_eq!(rest[0].packets_a_to_b + rest[0].packets_b_to_a, 5);
    }

    #[test]
    fn rst_closes_early() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        let syn = tcp_frame(x, y, 1234, 80, 0x02);
        let rst = tcp_frame(x, y, 1234, 80, 0x04);
        table.observe(ts(0), syn.len() as u64, &parse_info(&syn));
        table.observe(ts(1), rst.len() as u64, &parse_info(&rst));
        let expired = table.expire(ts(2));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].end, EndReason::Rst);
        assert!(expired[0].syn);
        assert!(expired[0].rst);
        assert!(table.is_empty());
    }

    #[test]
    fn fin_closes_at_next_expire() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        let fin = tcp_frame(x, y, 1234, 80, 0x01);
        table.observe(ts(0), fin.len() as u64, &parse_info(&fin));
        let expired = table.expire(ts(1));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].end, EndReason::Fin);
        assert!(expired[0].fin);
    }

    #[test]
    fn arp_ignored() {
        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        let frame = arp_frame();
        let info = parse_info(&frame);
        assert!(info.l3.is_none());
        table.observe(ts(0), frame.len() as u64, &info);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn icmp_keys_portless() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let payload = [8u8, 0, 0, 0, 0, 0, 0, 0];
        let ip = ipv4_packet_with(x, y, IpNextHeaderProtocols::Icmp, &payload);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        let info = parse_info(&frame);
        assert!(info.l3.is_some());
        assert!(info.l4.is_none());

        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        let len = frame.len() as u64;
        table.observe(ts(0), len, &parse_info(&frame));
        table.observe(ts(1), len, &parse_info(&frame));
        assert_eq!(table.len(), 1);

        let records = table.finish();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].packets_a_to_b, 2);
        assert_eq!(records[0].packets_b_to_a, 0);
        assert_eq!(records[0].bytes_a_to_b, 2 * len);
        assert_eq!(records[0].key.proto, 1);
        assert_eq!(records[0].key.a.port, None);
        assert_eq!(records[0].key.b.port, None);
    }

    #[test]
    fn non_ip_and_direction_mismatch_safety() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        // Truncated TCP: only 10 bytes of transport, so L4 is None but L3 is present.
        let truncated = [0u8; 10];
        let ip = ipv4_packet_with(x, y, IpNextHeaderProtocols::Tcp, &truncated);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        let info = parse_info(&frame);
        assert!(info.l3.is_some());
        assert!(info.l4.is_none());

        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        table.observe(ts(0), frame.len() as u64, &info);
        assert_eq!(table.len(), 1);
        let records = table.finish();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key.a.port, None);
        assert_eq!(records[0].key.b.port, None);
        assert_eq!(records[0].packets_a_to_b + records[0].packets_b_to_a, 1);
    }

    #[test]
    fn udp_segment_helper_counts_bytes() {
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let seg = udp_segment(1234, 53);
        let ip = ipv4_packet_with(x, y, IpNextHeaderProtocols::Udp, &seg);
        let frame = eth_frame(EtherTypes::Ipv4, &ip);
        let mut table = FlowTable::new(Duration::from_secs(60), Duration::from_secs(3600));
        table.observe(ts(0), frame.len() as u64, &parse_info(&frame));
        assert_eq!(table.len(), 1);
    }
}
