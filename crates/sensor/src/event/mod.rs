//! Zeek-inspired event model: one serde enum whose variants serialize as
//! tagged NDJSON records (`{"event":"conn",...}`).

pub mod pipeline;
pub mod sink;

pub use pipeline::EventPipeline;
pub use sink::{NdjsonSink, RetentionPolicy};

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unix-epoch seconds as f64 (millisecond-resolution timestamps).
/// Times before the epoch clamp to 0.0 (documented simplification).
pub fn unix_ts(ts: SystemTime) -> f64 {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as f64 + f64::from(d.subsec_millis()) / 1000.0,
        Err(_) => 0.0,
    }
}

/// Human name for an IP protocol number: 1 "icmp", 6 "tcp", 17 "udp",
/// 58 "icmpv6", anything else "other".
pub fn proto_name(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "other",
    }
}

/// One pipeline event, serialized as a tagged NDJSON record.
///
/// v0 protocol events carry their own uid from a global pipeline counter
/// (not the owning connection's uid) — correlation is by 5-tuple + ts;
/// documented simplification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Conn(ConnEvent),
    Dns(DnsEvent),
    Ssl(SslEvent),
    Http(HttpEvent),
    Arp(ArpEvent),
    Alert(AlertEvent),
    Heartbeat(HeartbeatEvent),
}

/// ARP packet record (RFC 826, Ethernet/IPv4 shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArpEvent {
    /// Unique event id from the global pipeline counter.
    pub uid: String,
    /// Capture timestamp, unix-epoch seconds.
    pub ts: f64,
    /// Sender protocol (IPv4) address — the address being claimed.
    pub src: String,
    /// Sender hardware address claiming `src`.
    pub sender_mac: String,
    /// Target protocol (IPv4) address.
    pub target_ip: String,
    /// Target hardware address; None when absent from the packet.
    pub target_mac: Option<String>,
    /// "request" or "reply".
    pub op: String,
    /// True for gratuitous ARP (sender IP equals target IP).
    pub is_gratuitous: bool,
}

/// Severity of a fired detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// Detection alert record produced by the rule engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvent {
    /// Unique event id (assigned by the detection engine).
    pub uid: String,
    /// Trigger timestamp, unix-epoch seconds.
    pub ts: f64,
    /// Detection name (e.g. "port-scan").
    pub name: String,
    /// How serious the detection is.
    pub severity: Severity,
    /// Host the alert is attributed to (the offender).
    pub src: String,
    /// Peer host when the detection has one.
    pub dst: Option<String>,
    /// Human-readable summary of what fired.
    pub message: String,
    /// uids of the events that triggered the alert.
    pub evidence: Vec<String>,
}

/// Connection summary record (Zeek `conn`-inspired).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnEvent {
    /// Unique event id from the global pipeline counter.
    pub uid: String,
    /// Capture timestamp, unix-epoch seconds.
    pub ts: f64,
    /// Connection duration in seconds (`last - first`).
    pub duration: f64,
    /// Human protocol name (see [`proto_name`]).
    pub proto: String,
    /// Connection state label (e.g. "SF").
    pub conn_state: String,
    /// Why the flow record was emitted (e.g. "fin").
    pub end_reason: String,
    /// Source IP address.
    pub src: String,
    /// Destination IP address.
    pub dst: String,
    /// Source port; None for portless protocols.
    pub src_port: Option<u16>,
    /// Destination port; None for portless protocols.
    pub dst_port: Option<u16>,
    /// Packet count in the `a → b` direction.
    pub pkts_a_to_b: u64,
    /// Byte count in the `a → b` direction.
    pub bytes_a_to_b: u64,
    /// Packet count in the `b → a` direction.
    pub pkts_b_to_a: u64,
    /// Byte count in the `b → a` direction.
    pub bytes_b_to_a: u64,
}

/// DNS query/response record (Zeek `dns`-inspired).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsEvent {
    /// Unique event id from the global pipeline counter.
    pub uid: String,
    /// Capture timestamp, unix-epoch seconds.
    pub ts: f64,
    /// Source IP address.
    pub src: String,
    /// Destination IP address.
    pub dst: String,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// DNS transaction id.
    pub txid: u16,
    /// True for a response, false for a query.
    pub is_response: bool,
    /// Response code; 0 when not a response.
    pub rcode: u8,
    /// Query name; None when absent or unparseable.
    pub query: Option<String>,
    /// Query type code; None when absent or unparseable.
    pub qtype: Option<u16>,
    /// Answer records as strings.
    pub answers: Vec<String>,
}

/// TLS handshake record (Zeek `ssl`-inspired).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SslEvent {
    /// Unique event id from the global pipeline counter.
    pub uid: String,
    /// Capture timestamp, unix-epoch seconds.
    pub ts: f64,
    /// Source IP address.
    pub src: String,
    /// Destination IP address.
    pub dst: String,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Negotiated TLS version label; None when not observed.
    pub version: Option<String>,
    /// Server Name Indication; None when not observed.
    pub sni: Option<String>,
    /// True when the handshake record was cut off by truncation.
    pub truncated: bool,
}

/// HTTP header-block record (Zeek `http`-inspired).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpEvent {
    /// Unique event id from the global pipeline counter.
    pub uid: String,
    /// Capture timestamp, unix-epoch seconds.
    pub ts: f64,
    /// Source IP address.
    pub src: String,
    /// Destination IP address.
    pub dst: String,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Whether the block parsed as a request or a response.
    pub kind: crate::proto::http::HttpKind,
    /// Requests; request method.
    pub method: Option<String>,
    /// Requests; request target (path).
    pub uri: Option<String>,
    /// Host header value.
    pub host: Option<String>,
    /// User-Agent header value.
    pub user_agent: Option<String>,
    /// Responses; numeric status code.
    pub status: Option<u16>,
}

/// Periodic pipeline counters record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatEvent {
    /// Capture timestamp, unix-epoch seconds.
    pub ts: f64,
    /// Total frames observed since pipeline start.
    pub total_frames: u64,
    /// Total bytes observed since pipeline start.
    pub bytes: u64,
    /// Flows currently live in the table.
    pub active_flows: usize,
    /// Total events emitted since pipeline start.
    pub events_emitted: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn conn_golden_string() {
        let event = Event::Conn(ConnEvent {
            uid: "conn1".to_string(),
            ts: 100.5,
            duration: 3.25,
            proto: "tcp".to_string(),
            conn_state: "SF".to_string(),
            end_reason: "fin".to_string(),
            src: "10.0.0.1".to_string(),
            dst: "10.0.0.2".to_string(),
            src_port: Some(1234),
            dst_port: Some(80),
            pkts_a_to_b: 5,
            bytes_a_to_b: 600,
            pkts_b_to_a: 4,
            bytes_b_to_a: 500,
        });
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"event":"conn","uid":"conn1","ts":100.5,"duration":3.25,"proto":"tcp","conn_state":"SF","end_reason":"fin","src":"10.0.0.1","dst":"10.0.0.2","src_port":1234,"dst_port":80,"pkts_a_to_b":5,"bytes_a_to_b":600,"pkts_b_to_a":4,"bytes_b_to_a":500}"#
        );
    }

    #[test]
    fn dns_serializes() {
        let event = Event::Dns(DnsEvent {
            uid: "dns1".to_string(),
            ts: 200.0,
            src: "10.0.0.1".to_string(),
            dst: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 53,
            txid: 0x1234,
            is_response: true,
            rcode: 0,
            query: Some("example.com".to_string()),
            qtype: Some(1),
            answers: vec!["1.2.3.4".to_string()],
        });
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["event"], "dns");
        assert_eq!(v["query"], "example.com");
        assert_eq!(v["qtype"], 1);
        assert_eq!(v["answers"][0], "1.2.3.4");
        assert_eq!(v["txid"], 0x1234);

        let none_q = Event::Dns(DnsEvent {
            uid: "dns2".to_string(),
            ts: 200.0,
            src: "10.0.0.1".to_string(),
            dst: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 53,
            txid: 1,
            is_response: false,
            rcode: 0,
            query: None,
            qtype: None,
            answers: vec![],
        });
        let vn: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&none_q).unwrap()).unwrap();
        assert!(vn["query"].is_null());
        assert!(vn["qtype"].is_null());
    }

    #[test]
    fn ssl_serializes() {
        let event = Event::Ssl(SslEvent {
            uid: "ssl1".to_string(),
            ts: 300.0,
            src: "10.0.0.1".to_string(),
            dst: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 443,
            version: Some("TLSv1.2".to_string()),
            sni: Some("example.com".to_string()),
            truncated: false,
        });
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["event"], "ssl");
        assert_eq!(v["version"], "TLSv1.2");
        assert_eq!(v["sni"], "example.com");
        assert_eq!(v["truncated"], false);
        assert_eq!(v["dst_port"], 443);

        let none_v = Event::Ssl(SslEvent {
            uid: "ssl2".to_string(),
            ts: 300.0,
            src: "10.0.0.1".to_string(),
            dst: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 443,
            version: None,
            sni: None,
            truncated: true,
        });
        let vn: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&none_v).unwrap()).unwrap();
        assert!(vn["version"].is_null());
        assert!(vn["sni"].is_null());
    }

    #[test]
    fn http_serializes() {
        let event = Event::Http(HttpEvent {
            uid: "http1".to_string(),
            ts: 400.0,
            src: "10.0.0.1".to_string(),
            dst: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 80,
            kind: crate::proto::http::HttpKind::Request,
            method: Some("GET".to_string()),
            uri: Some("/index.html".to_string()),
            host: Some("example.com".to_string()),
            user_agent: None,
            status: None,
        });
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["event"], "http");
        assert_eq!(v["kind"], "request");
        assert_eq!(v["method"], "GET");
        assert_eq!(v["uri"], "/index.html");
        assert_eq!(v["host"], "example.com");
        assert!(v["user_agent"].is_null());
        assert!(v["status"].is_null());
    }

    #[test]
    fn heartbeat_serializes() {
        let event = Event::Heartbeat(HeartbeatEvent {
            ts: 500.0,
            total_frames: 100,
            bytes: 64000,
            active_flows: 7,
            events_emitted: 42,
        });
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["event"], "heartbeat");
        assert_eq!(v["total_frames"], 100);
        assert_eq!(v["bytes"], 64000);
        assert_eq!(v["active_flows"], 7);
        assert_eq!(v["events_emitted"], 42);
    }

    #[test]
    fn arp_serializes() {
        let event = Event::Arp(ArpEvent {
            uid: "arp1".to_string(),
            ts: 600.0,
            src: "192.0.2.10".to_string(),
            sender_mac: "aa:bb:cc:01:02:03".to_string(),
            target_ip: "192.0.2.1".to_string(),
            target_mac: Some("00:00:00:00:00:00".to_string()),
            op: "request".to_string(),
            is_gratuitous: false,
        });
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["event"], "arp");
        assert_eq!(v["src"], "192.0.2.10");
        assert_eq!(v["sender_mac"], "aa:bb:cc:01:02:03");
        assert_eq!(v["op"], "request");
        assert_eq!(v["is_gratuitous"], false);

        let none_mac = Event::Arp(ArpEvent {
            uid: "arp2".to_string(),
            ts: 601.0,
            src: "192.0.2.10".to_string(),
            sender_mac: "aa:bb:cc:01:02:03".to_string(),
            target_ip: "192.0.2.1".to_string(),
            target_mac: None,
            op: "reply".to_string(),
            is_gratuitous: true,
        });
        let vn: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&none_mac).unwrap()).unwrap();
        assert!(vn["target_mac"].is_null());
        assert_eq!(vn["op"], "reply");
    }

    #[test]
    fn alert_serializes_with_lowercase_severity() {
        let event = Event::Alert(AlertEvent {
            uid: "alert1".to_string(),
            ts: 700.0,
            name: "port-scan".to_string(),
            severity: Severity::Medium,
            src: "192.0.2.66".to_string(),
            dst: Some("192.0.2.1".to_string()),
            message: "15 distinct ports in 60s".to_string(),
            evidence: vec!["conn1".to_string(), "conn2".to_string()],
        });
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["event"], "alert");
        assert_eq!(v["name"], "port-scan");
        assert_eq!(v["severity"], "medium");
        assert_eq!(v["dst"], "192.0.2.1");
        assert_eq!(v["evidence"][0], "conn1");

        let none_dst = Event::Alert(AlertEvent {
            uid: "alert2".to_string(),
            ts: 701.0,
            name: "dns-tunnel".to_string(),
            severity: Severity::High,
            src: "192.0.2.10".to_string(),
            dst: None,
            message: "long DNS labels".to_string(),
            evidence: vec![],
        });
        let vn: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&none_dst).unwrap()).unwrap();
        assert!(vn["dst"].is_null());
        assert_eq!(vn["severity"], "high");
    }

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
    }

    #[test]
    fn unix_ts_conversions() {
        assert_eq!(unix_ts(UNIX_EPOCH), 0.0);
        assert_eq!(unix_ts(UNIX_EPOCH + Duration::from_millis(1500)), 1.5);
    }

    #[test]
    fn proto_name_known_and_unknown() {
        assert_eq!(proto_name(1), "icmp");
        assert_eq!(proto_name(6), "tcp");
        assert_eq!(proto_name(17), "udp");
        assert_eq!(proto_name(58), "icmpv6");
        assert_eq!(proto_name(47), "other");
    }
}
