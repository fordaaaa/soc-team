//! DNS tunneling heuristics: oversized query labels and TXT floods.

use std::collections::BTreeMap;

use events::{AlertEvent, DnsEvent, Event, Severity};

use crate::Detection;

/// Fires when a source sends queries with suspiciously long labels
/// (encoded payload in a subdomain) or floods TXT queries.
#[derive(Debug, Clone)]
pub struct DnsTunnelDetector {
    /// Queries with any label longer than this many chars are flagged.
    pub max_label_len: usize,
    /// Minimum distinct TXT queries from one source within the window.
    pub min_txt_queries: usize,
    /// Sliding window length in seconds for the TXT rule.
    pub window_secs: f64,
}

impl Default for DnsTunnelDetector {
    fn default() -> Self {
        Self {
            max_label_len: 45,
            min_txt_queries: 20,
            window_secs: 60.0,
        }
    }
}

/// Longest dot-separated label in a query name.
fn longest_label(query: &str) -> usize {
    query
        .split('.')
        .map(|label| label.chars().count())
        .max()
        .unwrap_or(0)
}

impl Detection for DnsTunnelDetector {
    fn name(&self) -> &'static str {
        "dns-tunnel"
    }

    fn description(&self) -> &'static str {
        "dns tunneling: oversized query labels or txt query floods"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&mut self, events: &[Event]) -> Vec<AlertEvent> {
        let mut by_src: BTreeMap<String, Vec<DnsEvent>> = BTreeMap::new();
        for event in events {
            let Event::Dns(dns) = event else {
                continue;
            };
            if dns.query.is_some() {
                by_src.entry(dns.src.clone()).or_default().push(dns.clone());
            }
        }
        let mut alerts = Vec::new();
        for (src, mut group) in by_src {
            group.sort_by(|a, b| a.ts.total_cmp(&b.ts));
            alerts.extend(self.long_label_alerts(&src, &group));
            alerts.extend(self.txt_flood_alerts(&src, &group));
        }
        alerts
    }
}

impl DnsTunnelDetector {
    /// One alert per source whose queries carry an oversized label.
    fn long_label_alerts(&self, src: &str, group: &[DnsEvent]) -> Vec<AlertEvent> {
        let mut longest_seen = 0usize;
        let mut matched: Vec<&DnsEvent> = Vec::new();
        for dns in group {
            let Some(query) = &dns.query else {
                continue;
            };
            let label = longest_label(query);
            if label > self.max_label_len {
                longest_seen = longest_seen.max(label);
                matched.push(dns);
            }
        }
        if matched.is_empty() {
            return Vec::new();
        }
        let last = matched[matched.len() - 1].clone();
        vec![AlertEvent {
            uid: String::new(),
            ts: last.ts,
            name: self.name().to_string(),
            severity: self.severity(),
            src: src.to_string(),
            dst: Some(last.dst),
            message: format!("dns label of {longest_seen} chars from {src}"),
            evidence: matched.iter().take(10).map(|dns| dns.uid.clone()).collect(),
        }]
    }

    /// One alert per source flooding distinct TXT queries in one window.
    fn txt_flood_alerts(&self, src: &str, group: &[DnsEvent]) -> Vec<AlertEvent> {
        let txt: Vec<&DnsEvent> = group.iter().filter(|dns| dns.qtype == Some(16)).collect();
        if txt.is_empty() {
            return Vec::new();
        }
        // First occurrence per distinct query name keeps the window count
        // over distinct names.
        let mut seen: Vec<&str> = Vec::new();
        let mut distinct: Vec<&DnsEvent> = Vec::new();
        for dns in &txt {
            let Some(query) = dns.query.as_deref() else {
                continue;
            };
            if !seen.contains(&query) {
                seen.push(query);
                distinct.push(dns);
            }
        }
        let mut best: Option<(usize, usize, usize)> = None;
        let mut end = 0;
        for start in 0..distinct.len() {
            while end < distinct.len() && distinct[end].ts - distinct[start].ts <= self.window_secs
            {
                end += 1;
            }
            let count = end - start;
            let better = match best {
                Some((_, _, best_count)) => count > best_count,
                None => true,
            };
            if better {
                best = Some((start, end, count));
            }
        }
        let Some((start, end, count)) = best else {
            return Vec::new();
        };
        if count < self.min_txt_queries {
            return Vec::new();
        }
        let last = distinct[end - 1];
        vec![AlertEvent {
            uid: String::new(),
            ts: last.ts,
            name: self.name().to_string(),
            severity: self.severity(),
            src: src.to_string(),
            dst: Some(last.dst.clone()),
            message: format!("{count} txt queries within {}s", self.window_secs),
            evidence: distinct[start..end]
                .iter()
                .take(10)
                .map(|dns| dns.uid.clone())
                .collect(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns(uid: &str, ts: f64, src: &str, query: Option<String>, qtype: Option<u16>) -> Event {
        Event::Dns(DnsEvent {
            uid: uid.to_string(),
            ts,
            src: src.to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: 5353,
            dst_port: 53,
            txid: 0x1234,
            is_response: false,
            rcode: 0,
            query,
            qtype,
            answers: vec![],
        })
    }

    #[test]
    fn long_label_fires() {
        let events = vec![dns(
            "d1",
            1.0,
            "192.0.2.66",
            Some(format!("{}.example.com", "a".repeat(60))),
            Some(1),
        )];
        let mut detector = DnsTunnelDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "dns-tunnel");
        assert_eq!(alerts[0].severity, Severity::High);
        assert!(alerts[0].message.contains("60 chars"));
        assert!(alerts[0].uid.is_empty());
    }

    #[test]
    fn normal_labels_stay_quiet() {
        let events = vec![dns(
            "d1",
            1.0,
            "192.0.2.66",
            Some("example.com".to_string()),
            Some(1),
        )];
        let mut detector = DnsTunnelDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn txt_flood_fires() {
        let events: Vec<Event> = (0..20)
            .map(|i| {
                dns(
                    &format!("d{i}"),
                    i as f64,
                    "192.0.2.66",
                    Some(format!("q{i}.tunnel.example")),
                    Some(16),
                )
            })
            .collect();
        let mut detector = DnsTunnelDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].message.contains("20 txt queries within 60s"));
        assert_eq!(alerts[0].evidence.len(), 10);
    }

    #[test]
    fn txt_spread_over_window_stays_quiet() {
        let events: Vec<Event> = (0..20)
            .map(|i| {
                dns(
                    &format!("d{i}"),
                    i as f64 * 120.0,
                    "192.0.2.66",
                    Some(format!("q{i}.tunnel.example")),
                    Some(16),
                )
            })
            .collect();
        let mut detector = DnsTunnelDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn same_src_deduped_per_rule() {
        let events = vec![
            dns(
                "d1",
                1.0,
                "192.0.2.66",
                Some(format!("{}.example.com", "a".repeat(60))),
                Some(1),
            ),
            dns(
                "d2",
                2.0,
                "192.0.2.66",
                Some(format!("{}.example.com", "b".repeat(50))),
                Some(1),
            ),
        ];
        let mut detector = DnsTunnelDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].evidence, vec!["d1".to_string(), "d2".to_string()]);
    }

    #[test]
    fn a_records_do_not_trigger_txt_rule() {
        let events: Vec<Event> = (0..20)
            .map(|i| {
                dns(
                    &format!("d{i}"),
                    i as f64,
                    "192.0.2.66",
                    Some(format!("q{i}.example.com")),
                    Some(1),
                )
            })
            .collect();
        let mut detector = DnsTunnelDetector::default();
        assert!(detector.detect(&events).is_empty());
    }
}
