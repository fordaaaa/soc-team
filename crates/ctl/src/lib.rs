//! Operator-facing logic for the `socteam` control CLI — duration
//! parsing, flow-table formatting, heartbeat summarizing — kept out of
//! the binary so it is unit-testable.

pub mod demo;

use sensor::event::{AlertEvent, Event, HeartbeatEvent, Severity};
use std::time::Duration;
use store::FlowRow;

/// Parse a severity name (`low`/`medium`/`high`, case-insensitive).
pub fn parse_severity(s: &str) -> Option<Severity> {
    match s.trim().to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        _ => None,
    }
}

/// Parse a `--last` duration: an integer with an optional single suffix
/// `s`/`m`/`h` (case-insensitive). A bare number means seconds.
/// Returns None for empty, non-digit, negative, or unknown-suffix input.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (digits, unit) = match s.as_bytes()[s.len() - 1].to_ascii_lowercase() {
        b's' => (&s[..s.len() - 1], 1u64),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    Some(Duration::from_secs(n.saturating_mul(unit)))
}

/// Render flow rows as a fixed-width table: header line plus one line
/// per row, joined with '\n' (no trailing newline). Columns are
/// fixed-width except the `src -> dst` endpoint pair.
pub fn format_flows(rows: &[FlowRow]) -> String {
    let mut out = String::from(
        "ts            proto state  reason  src -> dst                                  a->b         b->a         dur",
    );
    for row in rows {
        out.push('\n');
        out.push_str(&format!(
            "{:<12} {:<6} {:<6} {:<7} {} -> {}  {:>5}p/{:>6}B {:>5}p/{:>6}B {:.3}s",
            row.ts,
            row.proto,
            row.conn_state,
            row.end_reason,
            endpoint(&row.src, row.src_port),
            endpoint(&row.dst, row.dst_port),
            row.pkts_a_to_b,
            row.bytes_a_to_b,
            row.pkts_b_to_a,
            row.bytes_b_to_a,
            row.duration,
        ));
    }
    out
}

/// Format one endpoint as `ip:port`; port `-` when the protocol has none.
fn endpoint(ip: &str, port: Option<u16>) -> String {
    format!(
        "{ip}:{}",
        port.map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string())
    )
}

/// One-line summary of the latest heartbeat event.
pub fn format_heartbeat(h: &HeartbeatEvent) -> String {
    format!(
        "heartbeat ts={} frames={} bytes={} active_flows={} events={}",
        h.ts, h.total_frames, h.bytes, h.active_flows, h.events_emitted
    )
}

/// Render alert events as a fixed-width table (header plus one line per
/// alert), joined with '\n'.
pub fn format_alerts(alerts: &[AlertEvent]) -> String {
    let mut out =
        String::from("ts            severity  name            src -> dst            message");
    for alert in alerts {
        out.push('\n');
        out.push_str(&format!(
            "{:<12} {:<8} {:<14} {} -> {}  {}",
            alert.ts,
            format!("{:?}", alert.severity).to_lowercase(),
            alert.name,
            alert.src,
            alert.dst.as_deref().unwrap_or("-"),
            alert.message,
        ));
    }
    out
}

/// The most recent heartbeat in `events`, or None when there is none.
pub fn latest_heartbeat(events: &[Event]) -> Option<&HeartbeatEvent> {
    events.iter().rev().find_map(|e| match e {
        Event::Heartbeat(h) => Some(h),
        _ => None,
    })
}

/// Split complete lines off the front of `buffer`, returning them plus
/// the byte count consumed (complete lines and their newlines only; the
/// unterminated tail stays). Bookkeeping is raw bytes, so lines with
/// invalid UTF-8 never desync the caller's file offsets — they are only
/// lossy-decoded for display.
pub fn drain_complete_lines(buffer: &mut Vec<u8>) -> (Vec<String>, usize) {
    let Some(end) = buffer.iter().rposition(|&b| b == b'\n') else {
        return (Vec::new(), 0);
    };
    let lines: Vec<String> = buffer[..end]
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect();
    let consumed = end + 1;
    buffer.drain(..consumed);
    (lines, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_suffixes() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("2H"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("  5s  "), Some(Duration::from_secs(5)));
    }

    #[test]
    fn parse_duration_rejects() {
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("-5s"), None);
        assert_eq!(parse_duration("1x"), None);
        assert_eq!(parse_duration("10 m"), None);
        assert_eq!(parse_duration("s"), None);
    }

    fn sample_row() -> FlowRow {
        FlowRow {
            uid: "conn1".to_string(),
            ts: 1770000000.5,
            duration: 1.25,
            proto: "tcp".to_string(),
            conn_state: "SF".to_string(),
            end_reason: "fin".to_string(),
            src: "192.0.2.10".to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: Some(4444),
            dst_port: Some(80),
            pkts_a_to_b: 5,
            bytes_a_to_b: 600,
            pkts_b_to_a: 4,
            bytes_b_to_a: 500,
        }
    }

    #[test]
    fn format_flows_golden() {
        let out = format_flows(&[sample_row()]);
        let mut lines = out.lines();
        assert_eq!(
            lines.next().unwrap(),
            "ts            proto state  reason  src -> dst                                  a->b         b->a         dur"
        );
        let row = lines.next().unwrap();
        assert!(row.contains("192.0.2.10:4444 -> 198.51.100.7:80"));
        assert!(row.contains("    5p/   600B"));
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn format_flows_empty_is_header_only() {
        let out = format_flows(&[]);
        assert_eq!(
            out,
            "ts            proto state  reason  src -> dst                                  a->b         b->a         dur"
        );
    }

    #[test]
    fn format_flows_portless_row() {
        let mut row = sample_row();
        row.src = "10.0.0.1".to_string();
        row.src_port = None;
        let out = format_flows(&[row]);
        assert!(out.contains("10.0.0.1:-"));
    }

    #[test]
    fn format_heartbeat_exact() {
        let h = HeartbeatEvent {
            ts: 1770000042.0,
            total_frames: 1234,
            bytes: 56789,
            active_flows: 7,
            events_emitted: 99,
        };
        assert_eq!(
            format_heartbeat(&h),
            "heartbeat ts=1770000042 frames=1234 bytes=56789 active_flows=7 events=99"
        );
    }

    #[test]
    fn latest_heartbeat_picks_last() {
        let mk = |ts: f64| {
            Event::Heartbeat(HeartbeatEvent {
                ts,
                total_frames: 1,
                bytes: 1,
                active_flows: 0,
                events_emitted: 1,
            })
        };
        let dns = Event::Dns(sensor::event::DnsEvent {
            uid: "dns1".to_string(),
            ts: 1.0,
            src: "192.0.2.10".to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: 5353,
            dst_port: 53,
            txid: 1,
            is_response: false,
            rcode: 0,
            query: None,
            qtype: None,
            answers: vec![],
        });
        let events = vec![mk(100.0), dns.clone(), mk(200.0)];
        let got = latest_heartbeat(&events).expect("heartbeat expected");
        assert_eq!(got.ts, 200.0);
        assert!(latest_heartbeat(&[dns]).is_none());
    }

    #[test]
    fn drain_complete_lines_splits_and_advances() {
        let mut buffer = b"a\nbb\nccc".to_vec();
        let (lines, consumed) = drain_complete_lines(&mut buffer);
        assert_eq!(lines, vec!["a".to_string(), "bb".to_string()]);
        assert_eq!(consumed, 5);
        assert_eq!(buffer, b"ccc");
    }

    #[test]
    fn drain_complete_lines_no_newline_consumes_nothing() {
        let mut buffer = b"partial line".to_vec();
        let (lines, consumed) = drain_complete_lines(&mut buffer);
        assert!(lines.is_empty());
        assert_eq!(consumed, 0);
        assert_eq!(buffer, b"partial line");
    }

    #[test]
    fn drain_complete_lines_invalid_utf8_keeps_byte_offsets() {
        // The invalid byte \xff renders as a 3-byte U+FFFD replacement
        // char, but the consumed count must stay in raw file bytes.
        let mut buffer = b"hi \xff there\nnext".to_vec();
        let (lines, consumed) = drain_complete_lines(&mut buffer);
        assert_eq!(lines, vec!["hi \u{FFFD} there".to_string()]);
        assert_eq!(consumed, 11);
        assert_eq!(buffer, b"next");
    }

    #[test]
    fn drain_complete_lines_skips_empty_lines() {
        let mut buffer = b"one\n\n\ntwo\n".to_vec();
        let (lines, consumed) = drain_complete_lines(&mut buffer);
        assert_eq!(lines, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(consumed, 10);
        assert!(buffer.is_empty());
    }

    #[test]
    fn parse_severity_names() {
        assert_eq!(parse_severity("low"), Some(Severity::Low));
        assert_eq!(parse_severity("MEDIUM"), Some(Severity::Medium));
        assert_eq!(parse_severity("high"), Some(Severity::High));
        assert_eq!(parse_severity("critical"), None);
    }

    fn sample_alert() -> AlertEvent {
        AlertEvent {
            uid: "alert1".to_string(),
            ts: 1770000000.0,
            name: "port-scan".to_string(),
            severity: Severity::Medium,
            src: "192.0.2.66".to_string(),
            dst: Some("198.51.100.7".to_string()),
            message: "15 distinct ports on 198.51.100.7 within 60s".to_string(),
            evidence: vec!["conn1".to_string()],
        }
    }

    #[test]
    fn format_alerts_golden() {
        let out = format_alerts(&[sample_alert()]);
        let mut lines = out.lines();
        assert_eq!(
            lines.next().unwrap(),
            "ts            severity  name            src -> dst            message"
        );
        let row = lines.next().unwrap();
        assert!(row.contains("medium   port-scan"));
        assert!(row.contains("192.0.2.66 -> 198.51.100.7"));
        assert!(row.contains("15 distinct ports"));
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn format_alerts_portless_dst() {
        let mut alert = sample_alert();
        alert.dst = None;
        let out = format_alerts(&[alert]);
        assert!(out.contains("192.0.2.66 -> -"));
    }
}
