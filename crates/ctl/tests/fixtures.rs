//! The committed demo fixture (`fixtures/demo`) must load cleanly and
//! fire every built-in detection — CI guards the reviewer one-liner.

use detect::{RuleEngine, SniWatchDetector};
use store::{EventStore, MemoryStore};

#[test]
fn committed_demo_fixture_fires_all_detections() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let dir = std::path::Path::new(manifest).join("../../fixtures/demo");
    let mut store = MemoryStore::new();
    store::load_dir(&mut store, &dir).expect("demo fixture loads");
    assert!(store.len().unwrap() >= 40, "fixture should carry 40 events");

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
            "expected {expected} to fire on the fixture, got: {names:?}"
        );
    }
}
