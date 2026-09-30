//! Vertical and horizontal port scan detection over conn events.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use events::{AlertEvent, ConnEvent, Event, Severity};

use crate::Detection;

/// Fires when one source touches many destination ports on one host
/// (vertical) or one destination port across many hosts (horizontal).
#[derive(Debug, Clone)]
pub struct PortScanDetector {
    /// Minimum distinct destination ports on one host within the window.
    pub min_ports: usize,
    /// Minimum distinct destination hosts for one destination port within the window.
    pub min_hosts: usize,
    /// Sliding window length in seconds.
    pub window_secs: f64,
}

impl Default for PortScanDetector {
    fn default() -> Self {
        Self {
            min_ports: 15,
            min_hosts: 30,
            window_secs: 60.0,
        }
    }
}

/// Densest sliding window over ts-sorted `events`: `Some((start, end, distinct))`
/// for the `[start, end)` window, None when no non-empty window exists.
fn best_window<K: Eq + Hash>(
    events: &[ConnEvent],
    key: impl Fn(&ConnEvent) -> K,
    window_secs: f64,
) -> Option<(usize, usize, usize)> {
    let mut counts: HashMap<K, usize> = HashMap::new();
    let mut best: Option<(usize, usize, usize)> = None;
    let mut end = 0;
    for start in 0..events.len() {
        while end < events.len() && events[end].ts - events[start].ts <= window_secs {
            *counts.entry(key(&events[end])).or_insert(0) += 1;
            end += 1;
        }
        if end > start {
            let better = match best {
                Some((_, _, count)) => counts.len() > count,
                None => true,
            };
            if better {
                best = Some((start, end, counts.len()));
            }
        }
        let leaving = key(&events[start]);
        if let Some(count) = counts.get_mut(&leaving) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&leaving);
            }
        }
    }
    best
}

impl Detection for PortScanDetector {
    fn name(&self) -> &'static str {
        "port-scan"
    }

    fn description(&self) -> &'static str {
        "vertical or horizontal scan: many ports on one host, or one port across many hosts"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&mut self, events: &[Event]) -> Vec<AlertEvent> {
        let mut alerts = Vec::new();
        let mut conns: Vec<ConnEvent> = Vec::new();
        for event in events {
            let Event::Conn(conn) = event else {
                continue;
            };
            if (conn.proto == "tcp" || conn.proto == "udp") && conn.dst_port.is_some() {
                conns.push(conn.clone());
            }
        }
        let mut vertical: BTreeMap<(String, String), Vec<ConnEvent>> = BTreeMap::new();
        let mut horizontal: BTreeMap<(String, u16), Vec<ConnEvent>> = BTreeMap::new();
        for conn in conns {
            vertical
                .entry((conn.src.clone(), conn.dst.clone()))
                .or_default()
                .push(conn.clone());
            if let Some(port) = conn.dst_port {
                horizontal
                    .entry((conn.src.clone(), port))
                    .or_default()
                    .push(conn);
            }
        }
        for ((src, dst), mut group) in vertical {
            group.sort_by(|a, b| a.ts.total_cmp(&b.ts));
            let Some((start, end, count)) =
                best_window(&group, |conn| conn.dst_port, self.window_secs)
            else {
                continue;
            };
            if count < self.min_ports {
                continue;
            }
            alerts.push(AlertEvent {
                uid: String::new(),
                ts: group[end - 1].ts,
                name: self.name().to_string(),
                severity: self.severity(),
                src: src.clone(),
                dst: Some(dst.clone()),
                message: format!(
                    "{count} distinct ports on {dst} within {}s",
                    self.window_secs
                ),
                evidence: group[start..end]
                    .iter()
                    .take(10)
                    .map(|conn| conn.uid.clone())
                    .collect(),
            });
        }
        for ((src, port), mut group) in horizontal {
            group.sort_by(|a, b| a.ts.total_cmp(&b.ts));
            let Some((start, end, count)) =
                best_window(&group, |conn| conn.dst.clone(), self.window_secs)
            else {
                continue;
            };
            if count < self.min_hosts {
                continue;
            }
            alerts.push(AlertEvent {
                uid: String::new(),
                ts: group[end - 1].ts,
                name: self.name().to_string(),
                severity: self.severity(),
                src,
                dst: None,
                message: format!(
                    "{count} hosts contacted on port {port} within {}s",
                    self.window_secs
                ),
                evidence: group[start..end]
                    .iter()
                    .take(10)
                    .map(|conn| conn.uid.clone())
                    .collect(),
            });
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-shape tcp conn used by detector tests.
    fn conn(uid: &str, ts: f64, src: &str, dst: &str, dst_port: u16) -> Event {
        Event::Conn(ConnEvent {
            uid: uid.to_string(),
            ts,
            duration: 1.5,
            proto: "tcp".to_string(),
            conn_state: "SF".to_string(),
            end_reason: "fin".to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            src_port: Some(4444),
            dst_port: Some(dst_port),
            pkts_a_to_b: 5,
            bytes_a_to_b: 600,
            pkts_b_to_a: 4,
            bytes_b_to_a: 500,
        })
    }

    #[test]
    fn vertical_scan_fires() {
        let events: Vec<Event> = (0..15)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64,
                    "192.0.2.66",
                    "198.51.100.7",
                    (i + 1) as u16,
                )
            })
            .collect();
        let mut detector = PortScanDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.name, "port-scan");
        assert_eq!(alert.severity, Severity::Medium);
        assert_eq!(alert.src, "192.0.2.66");
        assert_eq!(alert.dst.as_deref(), Some("198.51.100.7"));
        assert_eq!(alert.ts, 14.0);
        assert!(alert.message.contains("15 distinct ports"));
        assert_eq!(alert.evidence.len(), 10);
        assert_eq!(alert.evidence[0], "conn0");
        assert!(alert.uid.is_empty());
    }

    #[test]
    fn below_threshold_stays_quiet() {
        let events: Vec<Event> = (0..14)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64,
                    "192.0.2.66",
                    "198.51.100.7",
                    (i + 1) as u16,
                )
            })
            .collect();
        let mut detector = PortScanDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn window_exclusion_prevents_firing() {
        let events: Vec<Event> = (0..15)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64 * 120.0,
                    "192.0.2.66",
                    "198.51.100.7",
                    (i + 1) as u16,
                )
            })
            .collect();
        let mut detector = PortScanDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn horizontal_scan_fires() {
        let events: Vec<Event> = (0..30)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64,
                    "192.0.2.66",
                    &format!("198.51.100.{}", i + 1),
                    444,
                )
            })
            .collect();
        let mut detector = PortScanDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].dst.is_none());
        assert!(alerts[0].message.contains("30 hosts contacted on port 444"));
    }

    #[test]
    fn normal_traffic_stays_quiet() {
        let events: Vec<Event> = (0..3)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64,
                    "192.0.2.66",
                    "198.51.100.7",
                    80,
                )
            })
            .collect();
        let mut detector = PortScanDetector::default();
        assert!(detector.detect(&events).is_empty());
    }
}
