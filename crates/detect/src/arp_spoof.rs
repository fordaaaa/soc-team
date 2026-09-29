//! ARP spoofing detection: IP/MAC identity conflicts and gratuitous storms.

use std::collections::BTreeMap;

use sensor::event::{AlertEvent, ArpEvent, Event, Severity};

use crate::Detection;

/// Fires when one IP is claimed by multiple MACs inside the window, or
/// when one MAC floods gratuitous announcements.
#[derive(Debug, Clone)]
pub struct ArpSpoofDetector {
    /// Identity-conflict window in seconds.
    pub window_secs: f64,
    /// Minimum gratuitous announcements from one MAC to fire a storm alert.
    pub gratuitous_max: usize,
    /// Gratuitous-storm window in seconds.
    pub gratuitous_window_secs: f64,
}

impl Default for ArpSpoofDetector {
    fn default() -> Self {
        Self {
            window_secs: 300.0,
            gratuitous_max: 10,
            gratuitous_window_secs: 10.0,
        }
    }
}

impl Detection for ArpSpoofDetector {
    fn name(&self) -> &'static str {
        "arp-spoof"
    }

    fn description(&self) -> &'static str {
        "arp spoofing: one ip claimed by multiple macs, or a gratuitous-arp storm"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&mut self, events: &[Event]) -> Vec<AlertEvent> {
        let mut by_ip: BTreeMap<String, Vec<ArpEvent>> = BTreeMap::new();
        let mut storms: BTreeMap<String, Vec<ArpEvent>> = BTreeMap::new();
        for event in events {
            let Event::Arp(arp) = event else {
                continue;
            };
            by_ip.entry(arp.src.clone()).or_default().push(arp.clone());
            if arp.is_gratuitous {
                storms
                    .entry(arp.sender_mac.clone())
                    .or_default()
                    .push(arp.clone());
            }
        }
        let mut alerts = Vec::new();
        for (src, mut group) in by_ip {
            group.sort_by(|a, b| a.ts.total_cmp(&b.ts));
            alerts.extend(self.conflict_alerts(&src, &group));
        }
        for (mac, mut group) in storms {
            group.sort_by(|a, b| a.ts.total_cmp(&b.ts));
            alerts.extend(self.storm_alerts(&mac, &group));
        }
        alerts
    }
}

impl ArpSpoofDetector {
    /// One alert per IP claimed by two or more MACs in one window.
    fn conflict_alerts(&self, src: &str, group: &[ArpEvent]) -> Vec<AlertEvent> {
        let Some((start, end, count)) =
            best_distinct_window(group, |arp| arp.sender_mac.clone(), self.window_secs)
        else {
            return Vec::new();
        };
        if count < 2 {
            return Vec::new();
        }
        let last = &group[end - 1];
        vec![AlertEvent {
            uid: String::new(),
            ts: last.ts,
            name: self.name().to_string(),
            severity: self.severity(),
            src: src.to_string(),
            dst: None,
            message: format!("{src} claimed by {count} macs within {}s", self.window_secs),
            evidence: group[start..end]
                .iter()
                .take(10)
                .map(|arp| arp.uid.clone())
                .collect(),
        }]
    }

    /// One alert per MAC flooding gratuitous announcements in one window.
    fn storm_alerts(&self, mac: &str, group: &[ArpEvent]) -> Vec<AlertEvent> {
        let mut best: Option<(usize, usize, usize)> = None;
        let mut end = 0;
        for start in 0..group.len() {
            while end < group.len()
                && group[end].ts - group[start].ts <= self.gratuitous_window_secs
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
        if count < self.gratuitous_max {
            return Vec::new();
        }
        let last = &group[end - 1];
        vec![AlertEvent {
            uid: String::new(),
            ts: last.ts,
            name: self.name().to_string(),
            severity: self.severity(),
            src: last.src.clone(),
            dst: None,
            message: format!(
                "{count} gratuitous arps from {mac} within {}s",
                self.gratuitous_window_secs
            ),
            evidence: group[start..end]
                .iter()
                .take(10)
                .map(|arp| arp.uid.clone())
                .collect(),
        }]
    }
}

/// Densest sliding window over ts-sorted `events`, counting distinct
/// `key` values: `Some((start, end, distinct))`, None when empty.
fn best_distinct_window<K: Eq>(
    events: &[ArpEvent],
    key: impl Fn(&ArpEvent) -> K,
    window_secs: f64,
) -> Option<(usize, usize, usize)> {
    let mut best: Option<(usize, usize, usize)> = None;
    let mut end = 0;
    for start in 0..events.len() {
        while end < events.len() && events[end].ts - events[start].ts <= window_secs {
            end += 1;
        }
        if end > start {
            let distinct = {
                let mut seen: Vec<K> = Vec::new();
                for event in &events[start..end] {
                    let k = key(event);
                    if !seen.contains(&k) {
                        seen.push(k);
                    }
                }
                seen.len()
            };
            let better = match best {
                Some((_, _, best_count)) => distinct > best_count,
                None => true,
            };
            if better {
                best = Some((start, end, distinct));
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp(uid: &str, ts: f64, src: &str, sender_mac: &str, is_gratuitous: bool) -> Event {
        Event::Arp(ArpEvent {
            uid: uid.to_string(),
            ts,
            src: src.to_string(),
            sender_mac: sender_mac.to_string(),
            target_ip: "10.0.0.1".to_string(),
            target_mac: None,
            op: "request".to_string(),
            is_gratuitous,
        })
    }

    #[test]
    fn ip_claimed_by_two_macs_fires() {
        let events = vec![
            arp("a1", 0.0, "10.0.0.5", "aa:aa:aa:aa:aa:01", false),
            arp("a2", 1.0, "10.0.0.5", "aa:aa:aa:aa:aa:02", false),
            arp("a3", 2.0, "10.0.0.5", "aa:aa:aa:aa:aa:01", false),
            arp("a4", 3.0, "10.0.0.5", "aa:aa:aa:aa:aa:02", false),
        ];
        let mut detector = ArpSpoofDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "arp-spoof");
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].src, "10.0.0.5");
        assert!(alerts[0].message.contains("claimed by 2 macs"));
        assert!(alerts[0].uid.is_empty());
    }

    #[test]
    fn single_mac_stays_quiet() {
        let events: Vec<Event> = (0..4)
            .map(|i| {
                arp(
                    &format!("a{i}"),
                    i as f64,
                    "10.0.0.5",
                    "aa:aa:aa:aa:aa:01",
                    false,
                )
            })
            .collect();
        let mut detector = ArpSpoofDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn conflict_outside_window_stays_quiet() {
        let events = vec![
            arp("a1", 0.0, "10.0.0.5", "aa:aa:aa:aa:aa:01", false),
            arp("a2", 301.0, "10.0.0.5", "aa:aa:aa:aa:aa:02", false),
        ];
        let mut detector = ArpSpoofDetector::default();
        assert!(detector.detect(&events).is_empty());
    }

    #[test]
    fn gratuitous_storm_fires() {
        let events: Vec<Event> = (0..10)
            .map(|i| {
                arp(
                    &format!("a{i}"),
                    i as f64,
                    "10.0.0.5",
                    "aa:aa:aa:aa:aa:01",
                    true,
                )
            })
            .collect();
        let mut detector = ArpSpoofDetector::default();
        let alerts = detector.detect(&events);
        assert_eq!(alerts.len(), 1);
        assert!(
            alerts[0]
                .message
                .contains("10 gratuitous arps from aa:aa:aa:aa:aa:01 within 10s")
        );
        assert_eq!(alerts[0].src, "10.0.0.5");
    }

    #[test]
    fn gratuitous_below_threshold_stays_quiet() {
        let events: Vec<Event> = (0..9)
            .map(|i| {
                arp(
                    &format!("a{i}"),
                    i as f64,
                    "10.0.0.5",
                    "aa:aa:aa:aa:aa:01",
                    true,
                )
            })
            .collect();
        let mut detector = ArpSpoofDetector::default();
        assert!(detector.detect(&events).is_empty());
    }
}
