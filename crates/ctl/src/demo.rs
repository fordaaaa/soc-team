//! Deterministic synthetic scenario: baseline LAN traffic plus one
//! attack per built-in detection. Used by `socteam demo` and as the
//! end-to-end fixture for detection tests.

use sensor::event::{ArpEvent, ConnEvent, DnsEvent, Event, HeartbeatEvent, SslEvent};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Fixed base timestamp (unix seconds) so output is byte-identical
/// across runs.
const BASE_TS: f64 = 1_770_000_000.0;
/// NDJSON file name (load_dir sorts by path, so this stays ordered).
const FILE_NAME: &str = "events-1770000000000-0001.ndjson";
/// Watchlist written alongside the events for the SNI detection.
const WATCHLIST: &str = "# one domain per line\nnasty.example\nevilsite.example\n";

/// Generate the demo scenario into `dir`, returning the event count.
/// Creates `dir` if needed; events land in one NDJSON file plus a
/// `watchlist.txt`.
pub fn generate(dir: &Path) -> std::io::Result<usize> {
    fs_create_dir_all(dir)?;
    let mut events: Vec<Event> = Vec::new();
    let mut uid = 0u64;
    let mut tag = move |prefix: &str| {
        uid += 1;
        format!("{prefix}{uid}")
    };

    // Baseline: steady but irregular DNS + web traffic from a healthy
    // client (uniform spacing would itself look like beaconing).
    let baseline = [0.0, 7.0, 18.0, 26.0, 41.0, 55.0];
    for (i, offset) in baseline.iter().enumerate() {
        events.push(Event::Dns(DnsEvent {
            uid: tag("dns"),
            ts: BASE_TS + offset,
            src: "192.0.2.10".to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: 5353,
            dst_port: 53,
            txid: 0x1000 + i as u16,
            is_response: false,
            rcode: 0,
            query: Some("example.com.".to_string()),
            qtype: Some(1),
            answers: vec![],
        }));
        events.push(Event::Conn(ConnEvent {
            uid: tag("conn"),
            ts: BASE_TS + offset + 1.0,
            duration: 2.0,
            proto: "tcp".to_string(),
            conn_state: "SF".to_string(),
            end_reason: "fin".to_string(),
            src: "192.0.2.10".to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: Some(49152 + i as u16),
            dst_port: Some(80),
            pkts_a_to_b: 10,
            bytes_a_to_b: 1200,
            pkts_b_to_a: 8,
            bytes_b_to_a: 64000,
        }));
    }

    // Attack 1: vertical scan of 15 ports on one host.
    for i in 0..15u16 {
        events.push(Event::Conn(ConnEvent {
            uid: tag("conn"),
            ts: BASE_TS + 100.0 + f64::from(i),
            duration: 0.5,
            proto: "tcp".to_string(),
            conn_state: "S0".to_string(),
            end_reason: "rst".to_string(),
            src: "192.0.2.66".to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: Some(40000 + i),
            dst_port: Some(1000 + i),
            pkts_a_to_b: 1,
            bytes_a_to_b: 60,
            pkts_b_to_a: 1,
            bytes_b_to_a: 60,
        }));
    }

    // Attack 2: beaconing callbacks every 60 seconds.
    for i in 0..5u16 {
        events.push(Event::Conn(ConnEvent {
            uid: tag("conn"),
            ts: BASE_TS + 200.0 + f64::from(i) * 60.0,
            duration: 1.0,
            proto: "tcp".to_string(),
            conn_state: "SF".to_string(),
            end_reason: "fin".to_string(),
            src: "192.0.2.66".to_string(),
            dst: "198.51.100.99".to_string(),
            src_port: Some(41000 + i),
            dst_port: Some(443),
            pkts_a_to_b: 4,
            bytes_a_to_b: 320,
            pkts_b_to_a: 4,
            bytes_b_to_a: 280,
        }));
    }

    // Attack 3: dns tunneling via oversized labels.
    for i in 0..2 {
        events.push(Event::Dns(DnsEvent {
            uid: tag("dns"),
            ts: BASE_TS + 300.0 + f64::from(i),
            src: "192.0.2.20".to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: 5353,
            dst_port: 53,
            txid: 0x2000 + i,
            is_response: false,
            rcode: 0,
            query: Some(format!("{}.tunnel.example.", "a".repeat(60))),
            qtype: Some(16),
            answers: vec![],
        }));
    }

    // Attack 4: one IP claimed by dueling MACs.
    for i in 0..4 {
        events.push(Event::Arp(ArpEvent {
            uid: tag("arp"),
            ts: BASE_TS + 400.0 + f64::from(i),
            src: "10.0.0.5".to_string(),
            sender_mac: if i % 2 == 0 {
                "aa:aa:aa:aa:aa:01".to_string()
            } else {
                "aa:aa:aa:aa:aa:02".to_string()
            },
            target_ip: "10.0.0.1".to_string(),
            target_mac: None,
            op: "reply".to_string(),
            is_gratuitous: false,
        }));
    }

    // Attack 5: TLS to a watched server name.
    events.push(Event::Ssl(SslEvent {
        uid: tag("ssl"),
        ts: BASE_TS + 500.0,
        src: "192.0.2.66".to_string(),
        dst: "198.51.100.9".to_string(),
        src_port: 4444,
        dst_port: 443,
        version: Some("TLSv1.2".to_string()),
        sni: Some("evilsite.example".to_string()),
        truncated: false,
    }));

    events.push(Event::Heartbeat(HeartbeatEvent {
        ts: BASE_TS + 600.0,
        total_frames: 4200,
        bytes: 2_400_000,
        active_flows: 3,
        events_emitted: events.len() as u64 + 1,
    }));

    let file = fs::File::create(dir.join(FILE_NAME))?;
    let mut writer = BufWriter::new(file);
    for event in &events {
        serde_json::to_writer(&mut writer, event).map_err(std::io::Error::other)?;
        writeln!(writer)?;
    }
    writer.flush()?;
    std::fs::write(dir.join("watchlist.txt"), WATCHLIST)?;
    Ok(events.len())
}

fn fs_create_dir_all(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use detect::{RuleEngine, SniWatchDetector};
    use store::MemoryStore;

    #[test]
    fn demo_output_is_deterministic() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        generate(first.path()).unwrap();
        generate(second.path()).unwrap();
        let a = std::fs::read(first.path().join(FILE_NAME)).unwrap();
        let b = std::fs::read(second.path().join(FILE_NAME)).unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn demo_events_fire_all_five_detections() {
        let dir = tempfile::tempdir().unwrap();
        generate(dir.path()).unwrap();
        let mut store = MemoryStore::new();
        store::load_dir(&mut store, dir.path()).unwrap();
        let mut engine = RuleEngine::with_defaults();
        engine.register(Box::new(SniWatchDetector::new(vec![
            "evilsite.example".to_string(),
        ])));
        let alerts = engine.run(store.events());
        let names: Vec<&str> = alerts.iter().map(|a| a.name.as_str()).collect();
        for expected in [
            "port-scan",
            "beaconing",
            "dns-tunnel",
            "arp-spoof",
            "sni-watchlist",
        ] {
            assert!(
                names.contains(&expected),
                "expected {expected} to fire, got: {names:?}"
            );
        }
    }
}
