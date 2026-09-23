//! Frame-to-event pipeline: folds every frame into the flow table and
//! dispatches L4 payloads to the protocol parsers by port, producing
//! Zeek-style events. Time is caller-injected; no I/O.
//!
//! v0 simplifications (documented):
//! - Port dispatch: UDP with either port 53 -> DNS; TCP with either
//!   (src or dst) port 80 -> HTTP; TCP with either port 443 -> TLS.
//!   Anything else emits no protocol event (the flow is still tracked).
//! - TLS is ClientHello only: non-hello payloads naturally parse to
//!   `None` and emit nothing.
//! - DNS-over-TCP's 2-byte length prefix is NOT stripped: DNS parses the
//!   UDP-style payload only; TCP/53 payloads with a length prefix will
//!   fail to parse and emit nothing.
//! - Flow endpoints are direction-normalized: a conn event's `src` is
//!   endpoint `a` (the lesser endpoint), not necessarily the sender of
//!   any particular packet.
//! - `conn_state` uses a first-FIN simplification (no half-close
//!   tracking), Zeek-inspired.
//! - Protocol events carry their own uid from the global pipeline
//!   counter, not the owning connection's uid; correlate by 5-tuple + ts.

use std::time::{Duration, SystemTime};

use super::{ConnEvent, DnsEvent, Event, HeartbeatEvent, HttpEvent, SslEvent, proto_name, unix_ts};
use crate::flow::{EndReason, FlowRecord, FlowTable};
use crate::proto::{dns, http, l2, payload, tls};

/// Folds frames into a [`FlowTable`] and dispatches L4 payloads to the
/// protocol parsers by port, producing Zeek-style [`Event`]s.
pub struct EventPipeline {
    table: FlowTable,
    uid_seq: u64,
    frames: u64,
    bytes: u64,
    events_emitted: u64,
}

impl EventPipeline {
    /// Create an empty pipeline.
    ///
    /// Typical values (Zeek-inspired): idle 60s, active 3600s.
    pub fn new(idle_timeout: Duration, active_timeout: Duration) -> Self {
        Self {
            table: FlowTable::new(idle_timeout, active_timeout),
            uid_seq: 0,
            frames: 0,
            bytes: 0,
            events_emitted: 0,
        }
    }

    /// Fold one frame: count it, parse it, observe the flow, and dispatch
    /// the L4 payload to a protocol parser by port. Returns the (possibly
    /// empty) events produced by THIS frame.
    ///
    /// Port dispatch (v0 simplification): UDP either-port 53 -> DNS;
    /// TCP dst-or-src 80 -> HTTP; TCP dst-or-src 443 -> TLS (ClientHello
    /// only). DNS-over-TCP's 2-byte length prefix is NOT stripped.
    pub fn observe(&mut self, ts: SystemTime, wire_len: u64, frame: &[u8]) -> Vec<Event> {
        self.frames += 1;
        self.bytes += wire_len;

        let Some(info) = l2::parse(frame) else {
            return Vec::new();
        };
        self.table.observe(ts, wire_len, &info);

        let (Some(l3), Some(l4)) = (info.l3, info.l4) else {
            return Vec::new();
        };
        let Some(l4_bytes) = payload::l4_payload(frame) else {
            return Vec::new();
        };

        let src = l3.src.to_string();
        let dst = l3.dst.to_string();

        if l3.proto == 17 && (l4.src_port == 53 || l4.dst_port == 53) {
            let Some(summary) = dns::parse(l4_bytes) else {
                return Vec::new();
            };
            let uid = self.next_uid("dns");
            self.events_emitted += 1;
            return vec![Event::Dns(DnsEvent {
                uid,
                ts: unix_ts(ts),
                src,
                dst,
                src_port: l4.src_port,
                dst_port: l4.dst_port,
                txid: summary.transaction_id,
                is_response: summary.is_response,
                rcode: summary.rcode,
                query: summary.query,
                qtype: summary.qtype,
                answers: summary.answers,
            })];
        }

        if l3.proto == 6 && (l4.src_port == 80 || l4.dst_port == 80) {
            let Some(summary) = http::parse(l4_bytes) else {
                return Vec::new();
            };
            let uid = self.next_uid("http");
            self.events_emitted += 1;
            return vec![Event::Http(HttpEvent {
                uid,
                ts: unix_ts(ts),
                src,
                dst,
                src_port: l4.src_port,
                dst_port: l4.dst_port,
                kind: summary.kind,
                method: summary.method,
                uri: summary.uri,
                host: summary.host,
                user_agent: summary.user_agent,
                status: summary.status,
            })];
        }

        if l3.proto == 6 && (l4.src_port == 443 || l4.dst_port == 443) {
            let Some(summary) = tls::parse(l4_bytes) else {
                return Vec::new();
            };
            let uid = self.next_uid("ssl");
            self.events_emitted += 1;
            return vec![Event::Ssl(SslEvent {
                uid,
                ts: unix_ts(ts),
                src,
                dst,
                src_port: l4.src_port,
                dst_port: l4.dst_port,
                version: summary.version.map(|v| format!("0x{v:04x}")),
                sni: summary.sni,
                truncated: summary.truncated,
            })];
        }

        Vec::new()
    }

    /// Reap expired flows as conn events.
    pub fn expire(&mut self, now: SystemTime) -> Vec<Event> {
        let records = self.table.expire(now);
        records.into_iter().map(|r| self.conn_event(r)).collect()
    }

    /// Drain remaining flows as conn events (end_reason "eof").
    pub fn finish(self) -> Vec<Event> {
        let Self {
            table,
            mut uid_seq,
            mut events_emitted,
            ..
        } = self;
        table
            .finish()
            .into_iter()
            .map(|record| {
                uid_seq += 1;
                events_emitted += 1;
                build_conn_event(format!("conn{uid_seq}"), record)
            })
            .collect()
    }

    /// Build (and count) a heartbeat event from current counters.
    pub fn heartbeat(&mut self, ts: SystemTime) -> Event {
        self.events_emitted += 1;
        Event::Heartbeat(HeartbeatEvent {
            ts: unix_ts(ts),
            total_frames: self.frames,
            bytes: self.bytes,
            active_flows: self.table.len(),
            events_emitted: self.events_emitted,
        })
    }

    /// Number of flows currently live in the table.
    pub fn active_flows(&self) -> usize {
        self.table.len()
    }

    /// Total frames observed since pipeline start.
    pub fn total_frames(&self) -> u64 {
        self.frames
    }

    /// Total bytes observed since pipeline start (sum of `wire_len`).
    pub fn total_bytes(&self) -> u64 {
        self.bytes
    }

    /// Total events emitted since pipeline start (including heartbeats).
    pub fn events_emitted(&self) -> u64 {
        self.events_emitted
    }

    /// Next uid for `tag` (e.g. `format!("{tag}{uid_seq}")`).
    fn next_uid(&mut self, tag: &str) -> String {
        self.uid_seq += 1;
        format!("{tag}{}", self.uid_seq)
    }

    /// Build (and count) a conn event for one expired flow record.
    fn conn_event(&mut self, record: FlowRecord) -> Event {
        let uid = self.next_uid("conn");
        self.events_emitted += 1;
        build_conn_event(uid, record)
    }
}

/// Zeek-inspired connection-state label from the sticky TCP flags.
///
/// Non-TCP is "-"; otherwise `REJ` (RST with SYN seen), `RSTO` (RST
/// without SYN), `SF` (SYN with FIN seen), `S0` (SYN only), `OTH`
/// (no SYN). First-FIN simplification: half-close is not tracked.
fn conn_state(proto: u8, syn: bool, fin: bool, rst: bool) -> &'static str {
    if proto != 6 {
        "-"
    } else if syn && rst {
        "REJ"
    } else if rst {
        "RSTO"
    } else if syn && fin {
        "SF"
    } else if syn {
        "S0"
    } else {
        "OTH"
    }
}

/// Build a conn [`Event`] for one flow record under an assigned `uid`.
///
/// Note: `src`/`dst`/`src_port`/`dst_port` come from the
/// direction-normalized key endpoints `a`/`b` (`src` is endpoint `a`,
/// the lesser one), not from any particular packet's direction.
fn build_conn_event(uid: String, record: FlowRecord) -> Event {
    let end_reason = match record.end {
        EndReason::IdleTimeout => "idle",
        EndReason::ActiveTimeout => "active",
        EndReason::Fin => "fin",
        EndReason::Rst => "rst",
        EndReason::Eof => "eof",
    };
    Event::Conn(ConnEvent {
        uid,
        ts: unix_ts(record.first),
        duration: record
            .last
            .duration_since(record.first)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0),
        proto: proto_name(record.key.proto).to_string(),
        conn_state: conn_state(record.key.proto, record.syn, record.fin, record.rst).to_string(),
        end_reason: end_reason.to_string(),
        src: record.key.a.ip.to_string(),
        dst: record.key.b.ip.to_string(),
        src_port: record.key.a.port,
        dst_port: record.key.b.port,
        pkts_a_to_b: record.packets_a_to_b,
        bytes_a_to_b: record.bytes_a_to_b,
        pkts_b_to_a: record.packets_b_to_a,
        bytes_b_to_a: record.bytes_b_to_a,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};
    use pnet::datalink::MacAddr;
    use pnet_packet::MutablePacket;
    use pnet_packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
    use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet_packet::ipv4::MutableIpv4Packet;
    use pnet_packet::tcp::MutableTcpPacket;
    use pnet_packet::udp::MutableUdpPacket;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::UNIX_EPOCH;

    const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
    const EXTENSION_SERVER_NAME: u16 = 0x0000;
    const SERVER_NAME_HOST_NAME: u8 = 0x00;
    const RANDOM_LEN: usize = 32;

    fn ts(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn pipe() -> EventPipeline {
        EventPipeline::new(Duration::from_secs(60), Duration::from_secs(3600))
    }

    fn mac(byte: u8) -> MacAddr {
        MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, byte)
    }

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

    fn udp_frame(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let seg = udp_segment(sport, dport, payload);
        let ip = ipv4_packet_with(src, dst, IpNextHeaderProtocols::Udp, &seg);
        eth_frame(EtherTypes::Ipv4, &ip)
    }

    fn tcp_frame(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let seg = tcp_segment(sport, dport, flags, payload);
        let ip = ipv4_packet_with(src, dst, IpNextHeaderProtocols::Tcp, &seg);
        eth_frame(EtherTypes::Ipv4, &ip)
    }

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

    fn dns_query_payload() -> Vec<u8> {
        let name = Name::from_str("example.com.").unwrap();
        let mut message = Message::new();
        message
            .set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(name, RecordType::A));
        message.to_vec().unwrap()
    }

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
    fn dns_query_event() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let frame = udp_frame(x, y, 1234, 53, &dns_query_payload());
        let events = p.observe(ts(0), frame.len() as u64, &frame);
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Dns(d) => {
                assert!(d.uid.starts_with("dns"));
                assert_eq!(d.query, Some("example.com.".to_string()));
                assert_eq!(d.dst_port, 53);
                assert!(!d.is_response);
            }
            other => panic!("expected DnsEvent, got {other:?}"),
        }
        assert_eq!(p.active_flows(), 1);
    }

    #[test]
    fn http_request_event() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let payload = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame = tcp_frame(x, y, 4444, 80, 0x18, payload);
        let events = p.observe(ts(0), frame.len() as u64, &frame);
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Http(h) => {
                assert_eq!(h.kind, crate::proto::http::HttpKind::Request);
                assert_eq!(h.method, Some("GET".to_string()));
                assert_eq!(h.host, Some("example.com".to_string()));
            }
            other => panic!("expected HttpEvent, got {other:?}"),
        }
    }

    #[test]
    fn tls_hello_event() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let hello = build_hello(0x0303, Some(b"example.com"), &[0x1301], &[]);
        let frame = tcp_frame(x, y, 4444, 443, 0x18, &hello);
        let events = p.observe(ts(0), frame.len() as u64, &frame);
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Ssl(s) => {
                assert_eq!(s.sni, Some("example.com".to_string()));
                assert_eq!(s.version, Some("0x0303".to_string()));
            }
            other => panic!("expected SslEvent, got {other:?}"),
        }
    }

    #[test]
    fn idle_expiry_conn_event() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let syn = tcp_frame(x, y, 1234, 80, 0x02, &[]);
        let syn_ack = tcp_frame(y, x, 80, 1234, 0x12, &[]);
        let _ = p.observe(ts(0), syn.len() as u64, &syn);
        let _ = p.observe(ts(1), syn_ack.len() as u64, &syn_ack);
        let events = p.expire(ts(61));
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Conn(c) => {
                assert_eq!(c.conn_state, "S0");
                assert_eq!(c.end_reason, "idle");
                assert_eq!(c.duration, 1.0);
                assert_eq!(c.pkts_a_to_b, 1);
                assert_eq!(c.pkts_b_to_a, 1);
                assert_eq!(c.src, "10.0.0.1");
                assert_eq!(c.dst, "10.0.0.2");
                assert_eq!(c.src_port, Some(1234));
                assert_eq!(c.dst_port, Some(80));
            }
            other => panic!("expected ConnEvent, got {other:?}"),
        }
    }

    #[test]
    fn rst_is_rej() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let syn = tcp_frame(x, y, 1234, 80, 0x02, &[]);
        let rst = tcp_frame(x, y, 1234, 80, 0x04, &[]);
        let _ = p.observe(ts(0), syn.len() as u64, &syn);
        let _ = p.observe(ts(1), rst.len() as u64, &rst);
        let events = p.expire(ts(2));
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Conn(c) => {
                assert_eq!(c.conn_state, "REJ");
                assert_eq!(c.end_reason, "rst");
            }
            other => panic!("expected ConnEvent, got {other:?}"),
        }
    }

    #[test]
    fn udp_conn_state_dash() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let frame = udp_frame(x, y, 1234, 53, &[0xFF; 64]);
        let _ = p.observe(ts(0), frame.len() as u64, &frame);
        let events = p.expire(ts(61));
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Conn(c) => {
                assert_eq!(c.proto, "udp");
                assert_eq!(c.conn_state, "-");
            }
            other => panic!("expected ConnEvent, got {other:?}"),
        }
    }

    #[test]
    fn arp_counted_but_no_flow() {
        let mut p = pipe();
        let frame = arp_frame();
        let events = p.observe(ts(0), frame.len() as u64, &frame);
        assert!(events.is_empty());
        assert_eq!(p.total_frames(), 1);
        assert_eq!(p.active_flows(), 0);
    }

    #[test]
    fn unknown_port_no_protocol_event() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let frame = udp_frame(x, y, 1234, 9999, b"arbitrary-bytes");
        let events = p.observe(ts(0), frame.len() as u64, &frame);
        assert!(events.is_empty());
        assert_eq!(p.active_flows(), 1);
    }

    #[test]
    fn heartbeat_counts() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let f1 = udp_frame(x, y, 1234, 53, &dns_query_payload());
        let f2 = udp_frame(x, y, 1234, 53, &dns_query_payload());
        let _ = p.observe(ts(0), f1.len() as u64, &f1);
        let _ = p.observe(ts(1), f2.len() as u64, &f2);
        match p.heartbeat(ts(5)) {
            Event::Heartbeat(h) => {
                assert_eq!(h.total_frames, 2);
                assert!(h.active_flows >= 1);
                assert!(h.events_emitted >= 1);
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn finish_is_eof() {
        let mut p = pipe();
        let x = Ipv4Addr::new(10, 0, 0, 1);
        let y = Ipv4Addr::new(10, 0, 0, 2);
        let frame = tcp_frame(x, y, 1234, 80, 0x02, &[]);
        let _ = p.observe(ts(0), frame.len() as u64, &frame);
        let events = p.finish();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Conn(c) => assert_eq!(c.end_reason, "eof"),
            other => panic!("expected ConnEvent, got {other:?}"),
        }
    }
}
