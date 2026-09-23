# socteam

Local SOC sensor for your own private network: passive traffic visibility,
detection, and alerting that runs fully on-prem (Pi-scale, no cloud).

> Current status: **Phase 0 skeleton** — the workspace builds, the sensor
> opens an interface and prints packet counters. Detection rules, the
> DuckDB store, and the web console land in later phases (see `PLAN.md`).

## Layout

| Crate | Job |
|---|---|
| `sensor` | Capture + per-EtherType counters (`socteam-sensor` binary) |
| `detect` | Rule engine skeleton (YAML rules arrive in Phase 2) |
| `store` | Event store skeleton (DuckDB backend lands in Phase 1) |
| `console` | Web UI skeleton (Axum UI lands in Phase 1) |
| `ctl` | Control CLI (`socteam` binary: `version`, `status`) |

## Build

```sh
cargo build --release
```

## Run

List interfaces:

```sh
cargo run -p sensor -- --list-ifaces
```

Live capture needs permission to open the link layer — run as root:

```sh
sudo cargo run --release -p sensor -- --iface en0
```

(Replace `en0` with your interface name, e.g. `eth0` on Linux.)
Use `--interval <SECS>` to change the status-line period,
`--max-packets <N>` to stop after N packets, and `--promiscuous`
to enable promiscuous mode.

Control CLI:

```sh
cargo run -p ctl -- version
cargo run -p ctl -- status
```

## Capture notes

- macOS captures via BPF; Linux captures via AF_PACKET (non-promiscuous
  by default; pass `--promiscuous` to enable it).
- Phase 1 replaces the Linux datalink backend with AF_PACKET rings +
  eBPF filtering for zero-copy/low latency.
