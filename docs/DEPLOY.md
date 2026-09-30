# Homelab deployment guide

socteam as an appliance: a small box watching your own network's traffic
passively, running detections live, and pushing alerts to your phone —
"Pi-hole, but for the whole wire" (the two coexist happily; see below).

Everything here is for **networks you own**. The sensor records metadata
only (flow counters, DNS names, TLS server names) — it never decrypts TLS
or stores payloads. If other people use the network, be transparent with
them; that's both good practice and, in many places, the law.

## 1. Pick the hardware

| Option | Verdict | Why |
|---|---|---|
| **Raspberry Pi 5 (4 GB)** | recommended | Silent, ~5 W, ~$80 with PSU; aarch64 is already the repo's CI build target. Pair with a high-endurance SD card or a small USB3 SSD. |
| Spare mini-PC / old laptop (x86_64 or arm) | fine, free | More headroom for gigabit lines; the binaries build for it too. Laptop = built-in UPS. |
| Full desktop PC | overkill | Works, but 10× the power for the same job. |
| Arduino / ESP32 | wrong tool class | Microcontrollers have no OS, no userspace network stack, no Rust toolchain for DuckDB/Axum. Not a candidate. |

You also need a way to **see** the traffic (next section). A ~$25
managed switch (e.g. TP-Link TL-SG105E) covers most homes.

## 2. Put the sensor on the wire

The sensor is **passive** — it watches a copy of the traffic and never
sits in the forwarding path, so a sensor crash can never take the network
down. Two options, best first:

**Option A — switch mirror port (recommended).** On your managed switch,
mirror the port your router/uplink uses onto a spare port, and plug the
Pi there:

```
Internet ──► [router] ──► switch port 1  (mirrored to port 5)
                              └─► port 5 ──► Pi eth0 (capture iface)
                              └─► ports 2-4: your devices
```

Set `iface = "eth0"` and `promiscuous = true` in the config.

**Option B — run on the router host.** If your router *is* a Linux box
(or a Pi running a gateway setup), capture on its LAN bridge interface.
Every packet is already visible; no switch needed. Downside: the box now
runs your network too, so keep it simple.

What you *won't* see: wireless-client-to-wireless-client traffic that
never crosses the AP's wired uplink. Most home traffic does, so this is
rarely a practical gap.

**Pi-hole coexistence:** none needed. Keep Pi-hole as your DNS
server/ad-blocker; socteam watches DNS *traffic* on the wire without
being in the path. They answer different questions ("should this ad
resolve?" vs "who is my network talking to?").

## 3. Install

Grab the arm64 tarball from the repo's CI artifacts (Actions → any green
run → `socteam-arm64`), or build on the box:

```sh
git clone https://github.com/fordaaaa/soc-team && cd soc-team
cargo build --release -p sensor -p ctl -p console
sudo ./deploy/install.sh          # copies binaries, units, config
```

Then edit `/etc/socteam/socteam.toml`:

```toml
[sensor]
iface = "eth0"
promiscuous = true
events = "/var/lib/socteam/events"

[retention]          # keep the SD card bounded
max_dir_bytes = 536870912
max_age_secs = 604800

[alert]              # phone push via ntfy
ntfy_url = "https://ntfy.sh"        # or your self-hosted server
ntfy_topic = "a-long-random-private-string"
blind_secs = 900                    # ping me if the sensor goes blind

[detect]
live_window_secs = 600.0
cooldown_secs = 300.0
```

Start it:

```sh
sudo systemctl start socteam-sensor socteam-console
journalctl -u socteam-sensor -f        # watch for ALERT lines
```

The console is on `http://<pi>:8080` — note it has **no authentication**;
the systemd unit keeps the bind loopback-only, so reach it over SSH port
forwarding (`ssh -L 8080:localhost:8080 pi`) or put it behind your own
auth before exposing it.

## 4. Alerts on your phone

Two channels, both optional, both can run together:

**ntfy (push notifications).** Install the ntfy app
([ntfy.sh](https://ntfy.sh), or self-host for zero cloud), subscribe to
the `ntfy_topic` from the config (make it long and random — the topic
name *is* the credential), and detections push as they fire with
severity-mapped priority.

**Real text messages (email-to-SMS).** Every major carrier runs an email
gateway that delivers to your phone as SMS — free, no API account:

| Carrier | Address |
|---|---|
| Verizon | `5551234567@vtext.com` |
| AT&T | `5551234567@txt.att.net` |
| T-Mobile | `5551234567@tmomail.net` |
| Google Fi | `5551234567@msg.fi.google.com` |

Set the `[alert] mail_*` fields in the config (any SMTP account works;
Gmail needs an app password). Point `mail_to` at your gateway address
and every alert — including `new-device`, the "someone new joined my
network" text — arrives as an SMS. Keep the config file root-only
(`chmod 600`) since it holds the SMTP password.

Verify the whole chain without touching your network:

```sh
socteam-sensor --sim --pps 5000 --max-packets 4000 \
  --config /etc/socteam/socteam.toml
```

Sim mode injects periodic attack *drills* (a port scan, an ARP conflict),
so you should see `ALERT` lines and get pushes within seconds.

## 5. Day-2 operations

- **Disk**: retention caps in `[retention]` delete the oldest event
  files; 512 MiB ≈ months of home-LAN event history.
- **Logs**: `journalctl -u socteam-sensor`; events live in NDJSON under
  `/var/lib/socteam/events`.
- **Queries**: `socteam flows --events /var/lib/socteam/events --last 1h`,
  `socteam alerts --events ... --min-severity high`, or the console.
- **Updates**: rebuild, rerun `install.sh` (config is never overwritten),
  `systemctl restart`.

## 6. Known limits (honesty section)

- **Drop counters are unknown.** pnet (the capture library) exposes no
  packet-drop stats on any platform; the AF_PACKET-rings + eBPF backend
  that fixes this on Linux is planned but not built. The `sensor-blind`
  watch catches total capture death, not partial loss.
- **No inline blocking.** socteam watches; it never drops or shapes
  traffic. Enforcement is a far-future phase behind a hardware watchdog.
- **Console has no auth.** Keep it loopback-bound.
- **Detect-to-alert latency** is bounded by the status interval (default
  2 s) plus flow expiry for connection-based detections — fine for a
  home SOC, not a sub-second IPS.
- The 1 Mpps soak gate on real Pi hardware is still unproven; typical
  home traffic (≤ a few hundred Mbps) is well within measured capacity.
