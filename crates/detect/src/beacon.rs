//! Periodic beaconing detection over conn events (C2-style callbacks).

use std::collections::BTreeMap;

use sensor::event::{AlertEvent, ConnEvent, Event, Severity};

use crate::Detection;

/// Fires when one (src, dst, dst_port) pair produces at least
/// `min_flows` connections with near-uniform intervals inside a
/// plausible callback band.
#[derive(Debug, Clone)]
pub struct BeaconDetector {
    /// Minimum number of flows for one (src, dst, dst_port) pair.
    pub min_flows: usize,
    /// Minimum plausible callback interval in seconds.
    pub min_interval_secs: f64,
    /// Maximum plausible callback interval in seconds.
    pub max_interval_secs: f64,
    /// Maximum deviation from the mean interval, as a fraction of the mean.
    pub max_jitter: f64,
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self {
            min_flows: 5,
            min_interval_secs: 10.0,
            max_interval_secs: 3600.0,
            max_jitter: 0.2,
        }
    }
}

impl Detection for BeaconDetector {
    fn name(&self) -> &'static str {
        "beaconing"
    }

    fn description(&self) -> &'static str {
        "periodic callbacks: repeated connections at near-uniform intervals"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&mut self, events: &[Event]) -> Vec<AlertEvent> {
        let mut groups: BTreeMap<(String, String, u16), Vec<ConnEvent>> = BTreeMap::new();
        for event in events {
            let Event::Conn(conn) = event else {
                continue;
            };
            if (conn.proto == "tcp" || conn.proto == "udp") && conn.dst_port.is_some() {
                groups
                    .entry((conn.src.clone(), conn.dst.clone(), conn.dst_port.unwrap()))
                    .or_default()
                    .push(conn.clone());
            }
        }
        let mut alerts = Vec::new();
        for ((src, dst, port), mut group) in groups {
            group.sort_by(|a, b| a.ts.total_cmp(&b.ts));
            if group.len() < self.min_flows {
                continue;
            }
            let intervals: Vec<f64> = group
                .windows(2)
                .map(|pair| pair[1].ts - pair[0].ts)
                .collect();
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean < self.min_interval_secs || mean > self.max_interval_secs {
                continue;
            }
            let regular = intervals
                .iter()
                .all(|interval| (interval - mean).abs() <= self.max_jitter * mean);
            if !regular {
                continue;
            }
            alerts.push(AlertEvent {
                uid: String::new(),
                ts: group[group.len() - 1].ts,
                name: self.name().to_string(),
                severity: self.severity(),
                src,
                dst: Some(dst.clone()),
                message: format!(
                    "{} flows to {dst}:{port} at ~{mean:.1}s intervals",
                    group.len()
                ),
                evidence: group.iter().take(10).map(|conn| conn.uid.clone()).collect(),
            });
        }
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn regular_beaconing_fires() {
        let events: Vec<Event> = (0..5)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64 * 60.0,
                    "192.0.2.66",
                    "198.51.100.7",
                    443,
                )
            })
            .collect();
        let mut detector = BeaconDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "beaconing");
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].dst.as_deref(), Some("198.51.100.7"));
        assert_eq!(alerts[0].ts, 240.0);
        assert!(
            alerts[0]
                .message
                .contains("5 flows to 198.51.100.7:443 at ~60.0s intervals")
        );
        assert_eq!(alerts[0].evidence[0], "conn0");
        assert!(alerts[0].uid.is_empty());
    }

    #[test]
    fn irregular_intervals_stay_quiet() {
        let events: Vec<Event> = [0.0, 60.0, 200.0, 240.0, 500.0]
            .iter()
            .enumerate()
            .map(|(i, ts)| conn(&format!("conn{i}"), *ts, "192.0.2.66", "198.51.100.7", 443))
            .collect();
        let mut detector = BeaconDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn too_few_flows_stay_quiet() {
        let events: Vec<Event> = (0..4)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64 * 60.0,
                    "192.0.2.66",
                    "198.51.100.7",
                    443,
                )
            })
            .collect();
        let mut detector = BeaconDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn interval_out_of_band_stays_quiet() {
        let events: Vec<Event> = (0..5)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    i as f64 * 2.0,
                    "192.0.2.66",
                    "198.51.100.7",
                    443,
                )
            })
            .collect();
        let mut detector = BeaconDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn different_pair_is_separate_group() {
        let mut events: Vec<Event> = (0..5)
            .map(|i| {
                conn(
                    &format!("a{i}"),
                    i as f64 * 60.0,
                    "192.0.2.66",
                    "198.51.100.7",
                    443,
                )
            })
            .collect();
        events.extend((0..5).map(|i| {
            conn(
                &format!("b{i}"),
                i as f64 * 90.0,
                "192.0.2.66",
                "198.51.100.8",
                8443,
            )
        }));
        let mut detector = BeaconDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 2);
        // BTreeMap order: (src, dst, port) ascending.
        assert_eq!(alerts[0].dst.as_deref(), Some("198.51.100.7"));
        assert_eq!(alerts[1].dst.as_deref(), Some("198.51.100.8"));
    }
}
