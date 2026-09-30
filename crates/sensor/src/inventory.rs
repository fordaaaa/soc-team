//! Device inventory: MAC-address identity learned from ARP traffic,
//! persisted across restarts, with first-seen alerts.
//!
//! MACs (not IPs) are the stable device identity — DHCP churns IPs, but
//! a new MAC means new hardware joined the network. IPs come along as
//! "last seen at" hints and may be stale.

use events::{AlertEvent, Event, Severity};
use std::collections::BTreeMap;
use std::path::Path;

/// One known device.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeviceRecord {
    /// Last IP observed claiming this MAC.
    pub last_ip: String,
    /// Unix seconds when the MAC was first seen.
    pub first_seen: f64,
    /// Unix seconds when the MAC was last seen.
    pub last_seen: f64,
}

/// Learned inventory of devices, keyed by MAC address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Inventory {
    devices: BTreeMap<String, DeviceRecord>,
    /// Unix seconds of the last first-seen alert (rate limiting).
    last_alert_ts: Option<f64>,
    /// Minimum seconds between first-seen alerts. MAC randomization
    /// (iOS/Android privacy feature) and sim traffic can mint "new"
    /// MACs constantly; bursts are learned silently and reported at
    /// most this often.
    #[serde(default = "default_alert_gap")]
    alert_gap_secs: f64,
}

/// Default first-seen alert gap: one minute.
fn default_alert_gap() -> f64 {
    60.0
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            devices: BTreeMap::new(),
            last_alert_ts: None,
            alert_gap_secs: default_alert_gap(),
        }
    }
}

impl Inventory {
    /// An empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a persisted inventory; a missing file starts empty, a corrupt
    /// one starts empty with the error reported (learning is cheap, an
    /// alert storm from a fresh inventory is worse than losing state —
    /// so corrupt state resets rather than aborts the sensor).
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(inventory) => (inventory, None),
                Err(e) => (Self::new(), Some(format!("{}: {e}", path.display()))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::new(), None),
            Err(e) => (Self::new(), Some(format!("{}: {e}", path.display()))),
        }
    }

    /// Persist the inventory (best-effort atomic: write beside, rename).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Number of known devices.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True when nothing is known yet.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Known devices in MAC order (console/ctl views).
    pub fn devices(&self) -> &BTreeMap<String, DeviceRecord> {
        &self.devices
    }

    /// Observe one event; returns a first-seen alert when a previously
    /// unknown MAC appears. ARP events are the identity source (sender
    /// MAC + IP); other event kinds are ignored.
    pub fn observe(&mut self, event: &Event) -> Option<AlertEvent> {
        let Event::Arp(arp) = event else {
            return None;
        };
        // Gratuitous ARPs announce an address without proving presence of
        // traffic; still a valid identity claim — count them.
        let mac = arp.sender_mac.clone();
        let mut first_seen_alert = None;
        let record = self.devices.entry(mac.clone()).or_insert_with(|| {
            let may_alert = self
                .last_alert_ts
                .is_none_or(|last| arp.ts - last >= self.alert_gap_secs);
            if may_alert {
                self.last_alert_ts = Some(arp.ts);
                first_seen_alert = Some(AlertEvent {
                    uid: String::new(),
                    ts: arp.ts,
                    name: "new-device".to_string(),
                    severity: Severity::Medium,
                    src: arp.src.clone(),
                    dst: None,
                    message: format!("first time seeing {mac} claiming {}", arp.src),
                    evidence: vec![arp.uid.clone()],
                });
            }
            DeviceRecord {
                last_ip: arp.src.clone(),
                first_seen: arp.ts,
                last_seen: arp.ts,
            }
        });
        record.last_seen = arp.ts;
        record.last_ip = arp.src.clone();
        first_seen_alert
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::ArpEvent;

    fn arp(uid: &str, ts: f64, src: &str, mac: &str) -> Event {
        Event::Arp(ArpEvent {
            uid: uid.to_string(),
            ts,
            src: src.to_string(),
            sender_mac: mac.to_string(),
            target_ip: "10.0.0.1".to_string(),
            target_mac: None,
            op: "reply".to_string(),
            is_gratuitous: false,
        })
    }

    #[test]
    fn first_sighting_alerts_once() {
        let mut inv = Inventory::new();
        let first = inv.observe(&arp("a1", 100.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"));
        let alert = first.expect("first sighting must alert");
        assert_eq!(alert.name, "new-device");
        assert_eq!(alert.severity, Severity::Medium);
        assert_eq!(alert.src, "10.0.0.5");
        assert!(alert.message.contains("aa:aa:aa:aa:aa:01"));

        let again = inv.observe(&arp("a2", 200.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"));
        assert!(again.is_none(), "known MAC must not re-alert");
        assert_eq!(inv.devices()["aa:aa:aa:aa:aa:01"].last_seen, 200.0);
    }

    #[test]
    fn alert_bursts_are_rate_limited_but_learned() {
        let mut inv = Inventory::new();
        // Three unknown MACs in the same second: one alert, three learned.
        let first = inv.observe(&arp("a1", 100.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"));
        assert!(first.is_some());
        assert!(
            inv.observe(&arp("a2", 100.5, "10.0.0.6", "aa:aa:aa:aa:aa:02"))
                .is_none()
        );
        assert!(
            inv.observe(&arp("a3", 100.9, "10.0.0.7", "aa:aa:aa:aa:aa:03"))
                .is_none()
        );
        assert_eq!(inv.len(), 3, "suppressed MACs are still learned");
        // After the gap a genuinely new MAC alerts again.
        assert!(
            inv.observe(&arp("a4", 100.0 + 61.0, "10.0.0.8", "aa:aa:aa:aa:aa:04"))
                .is_some()
        );
    }

    #[test]
    fn ip_change_updates_hint_without_alert() {
        let mut inv = Inventory::new();
        inv.observe(&arp("a1", 100.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"));
        let moved = inv.observe(&arp("a2", 300.0, "10.0.0.99", "aa:aa:aa:aa:aa:01"));
        assert!(moved.is_none(), "DHCP renewal is not a new device");
        assert_eq!(inv.devices()["aa:aa:aa:aa:aa:01"].last_ip, "10.0.0.99");
    }

    #[test]
    fn non_arp_events_ignored() {
        let mut inv = Inventory::new();
        let dns = Event::Dns(events::DnsEvent {
            uid: "d1".to_string(),
            ts: 1.0,
            src: "10.0.0.5".to_string(),
            dst: "10.0.0.1".to_string(),
            src_port: 5353,
            dst_port: 53,
            txid: 1,
            is_response: false,
            rcode: 0,
            query: None,
            qtype: None,
            answers: vec![],
        });
        assert!(inv.observe(&dns).is_none());
        assert!(inv.is_empty());
    }

    #[test]
    fn persistence_roundtrip_and_corrupt_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let mut inv = Inventory::new();
        inv.observe(&arp("a1", 100.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"));
        inv.save(&path).unwrap();

        let (loaded, err) = Inventory::load(&path);
        assert!(err.is_none());
        assert_eq!(loaded.len(), 1);
        // Reloaded state: the same MAC is known, no re-alert.
        let mut loaded = loaded;
        assert!(
            loaded
                .observe(&arp("a2", 400.0, "10.0.0.5", "aa:aa:aa:aa:aa:01"))
                .is_none()
        );

        std::fs::write(&path, "not json").unwrap();
        let (reset, err) = Inventory::load(&path);
        assert!(reset.is_empty());
        assert!(err.is_some(), "corrupt state must be reported");

        let (fresh, err) = Inventory::load(&dir.path().join("missing.json"));
        assert!(fresh.is_empty());
        assert!(err.is_none(), "a missing file is a normal first boot");
    }
}
