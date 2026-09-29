//! Detection engine: batch rules over the sensor's event stream.
//!
//! Detections are stateful rules scanned over a slice of events
//! (offline batch semantics); each fires [`AlertEvent`]s with an empty
//! uid that the engine fills in. A live streaming loop can reuse the
//! same trait by feeding it sliding event windows.

use sensor::event::{AlertEvent, Event, Severity};

pub mod arp_spoof;
pub mod beacon;
pub mod dns_tunnel;
pub mod scan;
pub mod sni_watch;

/// One detection rule over the event stream.
pub trait Detection: Send {
    /// Short rule name (e.g. `port-scan`), used as the alert's `name`.
    fn name(&self) -> &'static str;
    /// Human-readable description of what the rule detects.
    fn description(&self) -> &'static str;
    /// Severity of the alerts this rule fires.
    fn severity(&self) -> Severity;
    /// Scan one batch of events and return the alerts that fired.
    /// Alerts must carry an empty uid; the engine assigns them.
    fn detect(&mut self, events: &[Event]) -> Vec<AlertEvent>;
}

/// Runs a set of [`Detection`] rules over event batches.
pub struct RuleEngine {
    detections: Vec<Box<dyn Detection>>,
    next_uid: u64,
}

impl RuleEngine {
    /// Create an engine with no rules.
    pub fn new() -> Self {
        Self {
            detections: Vec::new(),
            next_uid: 0,
        }
    }

    /// Add a detection to the engine.
    pub fn register(&mut self, detection: Box<dyn Detection>) {
        self.detections.push(detection);
    }

    /// Number of loaded detections.
    pub fn len(&self) -> usize {
        self.detections.len()
    }

    /// True when no detections are loaded.
    pub fn is_empty(&self) -> bool {
        self.detections.is_empty()
    }

    /// Run every detection over `events`; alerts come back in
    /// registration order with sequential `alert<N>` uids.
    pub fn run(&mut self, events: &[Event]) -> Vec<AlertEvent> {
        let mut alerts: Vec<AlertEvent> = self
            .detections
            .iter_mut()
            .flat_map(|detection| detection.detect(events))
            .collect();
        for alert in &mut alerts {
            self.next_uid += 1;
            alert.uid = format!("alert{}", self.next_uid);
        }
        alerts
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub detection emitting one fixed alert per call.
    struct StubDetection {
        alerts_per_run: usize,
    }

    impl Detection for StubDetection {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn description(&self) -> &'static str {
            "test stub"
        }
        fn severity(&self) -> Severity {
            Severity::Low
        }
        fn detect(&mut self, _events: &[Event]) -> Vec<AlertEvent> {
            (0..self.alerts_per_run)
                .map(|_| AlertEvent {
                    uid: String::new(),
                    ts: 1.0,
                    name: "stub".to_string(),
                    severity: Severity::Low,
                    src: "192.0.2.1".to_string(),
                    dst: None,
                    message: "stub fired".to_string(),
                    evidence: vec![],
                })
                .collect()
        }
    }

    fn sample_events() -> Vec<Event> {
        vec![]
    }

    #[test]
    fn new_engine_is_empty() {
        let mut engine = RuleEngine::new();
        assert!(engine.is_empty());
        assert!(engine.run(&sample_events()).is_empty());
        engine.register(Box::new(StubDetection { alerts_per_run: 1 }));
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn run_assigns_sequential_uids_in_registration_order() {
        let mut engine = RuleEngine::new();
        engine.register(Box::new(StubDetection { alerts_per_run: 2 }));
        engine.register(Box::new(StubDetection { alerts_per_run: 1 }));
        let alerts = engine.run(&sample_events());
        assert_eq!(alerts.len(), 3);
        assert_eq!(alerts[0].uid, "alert1");
        assert_eq!(alerts[1].uid, "alert2");
        assert_eq!(alerts[2].uid, "alert3");
        // Uids keep counting across runs.
        let again = engine.run(&sample_events());
        assert_eq!(again[0].uid, "alert4");
    }

    #[test]
    fn run_overwrites_empty_alert_uids() {
        let mut engine = RuleEngine::new();
        engine.register(Box::new(StubDetection { alerts_per_run: 1 }));
        let alerts = engine.run(&sample_events());
        assert_eq!(alerts[0].uid, "alert1");
        assert_ne!(alerts[0].uid, String::new());
    }
}
