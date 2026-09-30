//! SNI watchlist detection over TLS handshake events.

use std::collections::BTreeMap;

use events::{AlertEvent, Event, Severity};

use crate::Detection;

/// Fires when a client connects to a TLS server whose SNI matches the
/// configured watchlist (exact match or subdomain of a watched domain,
/// case-insensitive).
#[derive(Debug, Clone, Default)]
pub struct SniWatchDetector {
    /// Watched domains, compared case-insensitively.
    pub domains: Vec<String>,
}

impl SniWatchDetector {
    /// Build a detector for the given watchlist.
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains }
    }
}

/// Accumulated state for one (src, watched domain) group.
struct Group {
    /// Timestamp of the first matching event.
    first_ts: f64,
    /// Destination IP of the first matching event.
    first_dst: String,
    /// Matching event uids, capped at 10.
    evidence: Vec<String>,
}

impl Detection for SniWatchDetector {
    fn name(&self) -> &'static str {
        "sni-watchlist"
    }

    fn description(&self) -> &'static str {
        "tls connections to watched server names"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&mut self, events: &[Event]) -> Vec<AlertEvent> {
        if self.domains.is_empty() {
            return Vec::new();
        }
        // (src, matched domain) -> group, kept in (src, domain) order.
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for event in events {
            let Event::Ssl(ssl) = event else {
                continue;
            };
            let Some(sni) = ssl.sni.as_deref() else {
                continue;
            };
            let sni = sni.to_lowercase();
            let Some(domain) = self
                .domains
                .iter()
                .map(|domain| domain.to_lowercase())
                .find(|domain| sni == *domain || sni.ends_with(&format!(".{domain}")))
            else {
                continue;
            };
            let group = groups
                .entry((ssl.src.clone(), domain))
                .or_insert_with(|| Group {
                    first_ts: ssl.ts,
                    first_dst: ssl.dst.clone(),
                    evidence: Vec::new(),
                });
            if group.evidence.len() < 10 {
                group.evidence.push(ssl.uid.clone());
            }
        }
        groups
            .into_iter()
            .map(|((src, domain), group)| {
                let message = format!("{src} connected to watched domain {domain}");
                AlertEvent {
                    uid: String::new(),
                    ts: group.first_ts,
                    name: self.name().to_string(),
                    severity: self.severity(),
                    src,
                    dst: Some(group.first_dst),
                    message,
                    evidence: group.evidence,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::SslEvent;

    fn ssl(uid: &str, ts: f64, src: &str, sni: Option<&str>) -> Event {
        Event::Ssl(SslEvent {
            uid: uid.to_string(),
            ts,
            src: src.to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: 4444,
            dst_port: 443,
            version: Some("TLSv1.2".to_string()),
            sni: sni.map(str::to_string),
            truncated: false,
        })
    }

    #[test]
    fn watched_sni_fires() {
        let mut detector = SniWatchDetector::new(vec!["evil.example".to_string()]);
        let events = vec![ssl("e1", 1.0, "10.0.0.1", Some("evil.example"))];
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.name, "sni-watchlist");
        assert_eq!(alert.severity, Severity::Medium);
        assert!(alert.message.contains("watched domain evil.example"));
        assert_eq!(alert.dst.as_deref(), Some("198.51.100.7"));
        assert!(alert.uid.is_empty());
    }

    #[test]
    fn subdomain_matches() {
        let mut detector = SniWatchDetector::new(vec!["evil.example".to_string()]);
        let events = vec![ssl("e1", 1.0, "10.0.0.1", Some("c2.evil.example"))];
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].src, "10.0.0.1");
    }

    #[test]
    fn suffix_lookalike_does_not_match() {
        let mut detector = SniWatchDetector::new(vec!["evil.example".to_string()]);
        let events = vec![ssl("e1", 1.0, "10.0.0.1", Some("notevil.example"))];
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn unwatched_stays_quiet() {
        let mut detector = SniWatchDetector::new(vec!["evil.example".to_string()]);
        let events = vec![ssl("e1", 1.0, "10.0.0.1", Some("example.org"))];
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn case_insensitive_and_deduped() {
        let mut detector = SniWatchDetector::new(vec!["evil.example".to_string()]);
        let events = vec![
            ssl("e1", 1.0, "10.0.0.1", Some("EVIL.example")),
            ssl("e2", 2.0, "10.0.0.1", Some("evil.EXAMPLE")),
        ];
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].ts, 1.0);
        assert_eq!(alerts[0].evidence, vec!["e1".to_string(), "e2".to_string()]);
    }

    #[test]
    fn empty_watchlist_fires_nothing() {
        let mut detector = SniWatchDetector::default();
        let events = vec![ssl("e1", 1.0, "10.0.0.1", Some("evil.example"))];
        assert!(detector.detect(&events).is_empty());
    }
}
