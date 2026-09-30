# Detections

The detection engine (`crates/detect`) runs batch rules over the sensor's
event stream. Every detection ships with synthetic-fixture tests plus a
purple-team integration test (`crates/detect/tests/purple.rs`) that pushes
real attack frames through the sensor pipeline and asserts the alert fires.
No detection is documented here without a test that proves it.

## Coverage

| Detection | Name | Layer | Severity | Default threshold | Tests |
|---|---|---|---|---|---|
| Port scan | `port-scan` | TCP/UDP flows | medium | 15 ports/host or 30 hosts/port in 60s | unit + purple |
| Beaconing | `beaconing` | TCP/UDP flows | high | ≥5 flows, near-uniform intervals, 10s–1h band | unit + purple |
| DNS tunneling | `dns-tunnel` | DNS | high | label >45 chars, or 20 distinct TXT queries in 60s | unit + purple |
| ARP spoofing | `arp-spoof` | ARP (L2) | high | 2 MACs claim one IP in 300s, or 10 gratuitous in 10s | unit + purple |
| SNI watchlist | `sni-watchlist` | TLS metadata | medium | operator-supplied domain list | unit + purple |
| New device | `new-device` | ARP (L2) | medium | first-seen MAC, rate-limited to 1/min | unit + e2e |

## How the engine works

- The sensor pipeline emits Zeek-style events (conn, dns, ssl, http, arp)
  as NDJSON; the engine scans slices of those events offline.
- Each detection implements the `Detection` trait: `name`, `description`,
  `severity`, and `detect(&mut events) -> Vec<AlertEvent>`.
- `RuleEngine::with_defaults()` loads all five at default thresholds; each
  threshold is a public struct field, so operators can tune or replace any
  rule before running.
- Alerts are events too (`{"event":"alert",...}`) — they flow through the
  same store, CLI, and console as sensor events.

Run the defaults over an events directory:

```sh
socteam detect --events DIR --out alerts.ndjson --watchlist watchlist.txt
socteam alerts --events DIR
```

## Port scan (`port-scan`)

Two rules in one detector, both over conn events:

- **Vertical**: one source touching ≥ 15 distinct destination ports on one
  destination within a 60s sliding window (`min_ports`).
- **Horizontal**: one source touching ≥ 30 distinct destinations on a
  single destination port within the window (`min_hosts`).

Windows are two-pointer sweeps over ts-sorted events per (src, dst) group,
so detection is exact over the batch (no fixed-bucket aliasing). The alert
carries the offending source, the target (vertical only), and up to 10
evidence uids. **Proven by**: `vertical_scan_fires`,
`window_exclusion_prevents_firing`, `horizontal_scan_fires`, and the
purple-team `syn_sweep_fires_port_scan` (15 real SYN frames through the
pipeline).

## Beaconing (`beaconing`)

Groups conn events by `(src, dst, dst_port)`; a group with ≥ 5 flows
(`min_flows`) whose consecutive intervals average inside the 10s–1h
callback band and never deviate from the mean by more than 20%
(`max_jitter`) fires once per group. Regular callbacks are the classic
C2 signature; near-uniform spacing is what separates them from human
browsing. **Proven by**: `regular_beaconing_fires`,
`irregular_intervals_stay_quiet`, `interval_out_of_band_stays_quiet`, and
purple-team `regular_callbacks_fire_beaconing`.

## DNS tunneling (`dns-tunnel`)

Two heuristics over DNS queries:

- **Long labels**: any dot-separated label longer than 45 characters
  (`max_label_len`) — the standard shape of base32/base64-encoded payload
  riding in a subdomain.
- **TXT flood**: ≥ 20 distinct TXT queries (`min_txt_queries`) from one
  source inside a 60s window — tunnels often stage data in TXT bursts.

**Proven by**: `long_label_fires`, `txt_flood_fires`,
`txt_spread_over_window_stays_quiet`, `a_records_do_not_trigger_txt_rule`,
and purple-team `long_label_query_fires_dns_tunnel` (a real hickory-encoded
DNS frame through the pipeline).

## ARP spoofing (`arp-spoof`)

Two rules over ARP events:

- **Identity conflict**: one sender IP claimed by ≥ 2 distinct sender MACs
  inside a 300s window — the core of ARP spoofing / man-in-the-middle
  positioning.
- **Gratuitous storm**: ≥ 10 gratuitous announcements from one MAC in 10s
  — cache-poisoning floods.

**Proven by**: `ip_claimed_by_two_macs_fires`,
`conflict_outside_window_stays_quiet`, `gratuitous_storm_fires`, and
purple-team `dueling_macs_fire_arp_spoof` (raw ARP reply frames with
competing MACs through the pipeline).

## SNI watchlist (`sni-watchlist`)

Matches the Server Name Indication of TLS handshakes against an
operator-supplied domain list (case-insensitive; exact or subdomain
match — `notevil.example` does not match `evil.example`). One alert per
(source, domain) pair with first-seen timestamp. The default watchlist is
empty: this rule only fires when you give it domains, via
`--watchlist` (one domain per line, `#` comments) or by registering
`SniWatchDetector::new(vec![...])`. **Proven by**: `watched_sni_fires`,
`suffix_lookalike_does_not_match`, `case_insensitive_and_deduped`.

## New device (`new-device`)

The sensor learns device identity from ARP traffic (sender MAC + claimed
IP), persists what it knows to `devices.json` beside the event files,
and fires a `new-device` alert the first time an unknown MAC appears —
"something new just joined the network." MACs are the identity (IPs
churn with DHCP); a known device moving to a new IP updates its hint
without alerting. Bursts of unknown MACs — MAC randomization on modern
phones, or synthetic traffic — are learned silently and reported at most
once per minute, so privacy features don't cause alert storms. **Proven
by**: `first_sighting_alerts_once`, `ip_change_updates_hint_without_alert`,
`alert_bursts_are_rate_limited_but_learned`,
`persistence_roundtrip_and_corrupt_reset`; e2e: two identical sim runs
alert once, then never again.

## Known limits (honesty section)

- Detection is batch/offline: run `socteam detect` over an events
  directory. A live in-pipeline hook is planned (the trait is designed so
  a streaming loop can feed sliding windows to the same rules).
- Conn events need flow expiry, so scan/beacon alerts appear after flows
  close (idle timeout or EOF), not per-packet.
- The SNI rule is metadata-only by design — no TLS interception anywhere
  in this project (see `PLAN.md` non-goals).
- Thresholds are starting points, not tuned baselines; the demo fixture
  (`fixtures/demo`) is the reference for what fires.
