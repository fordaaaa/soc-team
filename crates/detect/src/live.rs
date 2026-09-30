//! Live detection: a sliding event window feeding the batch rules.
//!
//! The built-in detectors are batch scanners over event slices; a live
//! sensor re-runs them on an overlapping window every tick. Two pieces
//! of bookkeeping make that safe: the window evicts events older than
//! `window_secs`, and a per-`(name, src)` cooldown suppresses the same
//! alert re-firing on every overlapping scan.

use std::collections::{HashMap, VecDeque};

use sensor::event::{AlertEvent, Event};

use crate::RuleEngine;

/// Hard cap on windowed events, so a burst can never balloon memory.
const MAX_WINDOW_EVENTS: usize = 10_000;

/// Batch rules over a sliding event window with cooldown suppression.
pub struct LiveEngine {
    engine: RuleEngine,
    window: VecDeque<Event>,
    window_secs: f64,
    cooldown_secs: f64,
    last_fired: HashMap<(String, String), f64>,
}

impl LiveEngine {
    /// Wrap a rule engine with a window of `window_secs` and a
    /// per-alert cooldown of `cooldown_secs`.
    pub fn new(engine: RuleEngine, window_secs: f64, cooldown_secs: f64) -> Self {
        Self {
            engine,
            window: VecDeque::new(),
            window_secs,
            cooldown_secs,
            last_fired: HashMap::new(),
        }
    }

    /// Number of events currently in the window.
    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    /// Add one event to the window; its own timestamp drives eviction.
    pub fn push(&mut self, event: &Event) {
        self.window.push_back(event.clone());
        let newest_ts = event_ts(event);
        while let Some(oldest) = self.window.front() {
            let expired = newest_ts - event_ts(oldest) > self.window_secs;
            if expired || self.window.len() > MAX_WINDOW_EVENTS {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Scan the whole window and return alerts that are not under
    /// cooldown, in engine order. `ts` is the current time in unix
    /// seconds (injected so the engine stays deterministic in tests).
    pub fn tick(&mut self, ts: f64) -> Vec<AlertEvent> {
        let events: Vec<Event> = self.window.iter().cloned().collect();
        let mut out = Vec::new();
        for alert in self.engine.run(&events) {
            let key = (alert.name.clone(), alert.src.clone());
            let suppressed = self
                .last_fired
                .get(&key)
                .is_some_and(|last| ts - *last < self.cooldown_secs);
            if suppressed {
                continue;
            }
            self.last_fired.insert(key, ts);
            out.push(alert);
        }
        // Bound cooldown memory: entries expire long after they stop
        // suppressing anything.
        self.last_fired
            .retain(|_, last| ts - *last < self.cooldown_secs * 10.0);
        out
    }
}

/// Timestamp of any event variant (unix seconds).
fn event_ts(event: &Event) -> f64 {
    match event {
        Event::Conn(e) => e.ts,
        Event::Dns(e) => e.ts,
        Event::Ssl(e) => e.ts,
        Event::Http(e) => e.ts,
        Event::Arp(e) => e.ts,
        Event::Alert(e) => e.ts,
        Event::Heartbeat(e) => e.ts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensor::event::{ConnEvent, Severity};

    fn conn(uid: &str, ts: f64, src: &str, dst: &str, dst_port: u16) -> Event {
        Event::Conn(ConnEvent {
            uid: uid.to_string(),
            ts,
            duration: 0.5,
            proto: "tcp".to_string(),
            conn_state: "S0".to_string(),
            end_reason: "rst".to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            src_port: Some(40000),
            dst_port: Some(dst_port),
            pkts_a_to_b: 1,
            bytes_a_to_b: 60,
            pkts_b_to_a: 1,
            bytes_b_to_a: 60,
        })
    }

    fn heartbeat(ts: f64) -> Event {
        Event::Heartbeat(sensor::event::HeartbeatEvent {
            ts,
            total_frames: 1,
            bytes: 1,
            active_flows: 0,
            events_emitted: 1,
        })
    }

    /// 15-port scan from one source inside the window.
    fn scan(src: &str) -> Vec<Event> {
        (0..15)
            .map(|i| {
                conn(
                    &format!("c{src}{i}"),
                    i as f64,
                    src,
                    "198.51.100.7",
                    1000 + i as u16,
                )
            })
            .collect()
    }

    fn engine() -> LiveEngine {
        LiveEngine::new(RuleEngine::with_defaults(), 600.0, 300.0)
    }

    #[test]
    fn live_fires_then_cooldowns() {
        let mut live = engine();
        for event in scan("192.0.2.66") {
            live.push(&event);
        }
        let alerts = live.tick(14.0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].name, "port-scan");

        // Overlapping window, same source: suppressed by cooldown.
        assert!(live.tick(20.0).is_empty());

        // After the cooldown the same activity alerts again.
        let again = live.tick(20.0 + 300.0);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].name, "port-scan");
    }

    #[test]
    fn different_src_is_not_suppressed() {
        let mut live = engine();
        for event in scan("192.0.2.66").into_iter().chain(scan("192.0.2.99")) {
            live.push(&event);
        }
        let alerts = live.tick(14.0);
        assert_eq!(alerts.len(), 2);
        let srcs: Vec<&str> = alerts.iter().map(|a| a.src.as_str()).collect();
        assert!(srcs.contains(&"192.0.2.66"));
        assert!(srcs.contains(&"192.0.2.99"));
    }

    #[test]
    fn window_evicts_aged_out_events() {
        let mut live = engine();
        for event in scan("192.0.2.66") {
            live.push(&event);
        }
        // Push the window far past the scan activity.
        live.push(&heartbeat(1000.0));
        assert!(live.tick(1000.0).is_empty(), "aged-out scan must not fire");
    }

    #[test]
    fn heartbeats_alone_stay_quiet() {
        let mut live = engine();
        for i in 0..50 {
            live.push(&heartbeat(i as f64));
        }
        assert!(live.tick(50.0).is_empty());
    }

    #[test]
    fn severity_carries_through() {
        let mut live = engine();
        for event in scan("192.0.2.66") {
            live.push(&event);
        }
        let alerts = live.tick(14.0);
        assert_eq!(alerts[0].severity, Severity::Medium);
    }
}
