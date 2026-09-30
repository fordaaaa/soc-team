//! `socteam-sensor` — packet counter + Zeek-style event emitter.
//!
//! Captures an interface via `pnet::datalink`, replays a pcap file, or
//! generates deterministic synthetic traffic (`--sim`, no root needed);
//! prints per-interval frame counters to stdout and (with `--events <DIR>`)
//! writes conn/dns/ssl/http/arp/heartbeat events as rotating NDJSON.
//!
//! Phase 1 replaces the datalink backend on Linux with AF_PACKET rings +
//! eBPF filtering for zero-copy/low latency.

use anyhow::{Context, Result, bail};
use clap::Parser;
use detect::LiveEngine;
use sensor::count::LinkCounter;
use sensor::event::{Event, EventPipeline, NdjsonSink, unix_ts};
use sensor::iface::list_interfaces;
use sensor::inventory::Inventory;
use sensor::notify::{Channel, Dispatch, Ntfy};
use sensor::source::{
    DatalinkSource, PacketSource, PcapSource, SimSource, SourceItem, now_iso8601,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Local-network security sensor.
#[derive(Debug, Parser)]
#[command(
    name = "socteam-sensor",
    version,
    about = "socteam local-network sensor"
)]
struct Args {
    /// TOML config file; every setting can also be given as a flag, and
    /// flags override the file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Interface to capture on (e.g. en0, eth0).
    #[arg(long)]
    iface: Option<String>,

    /// Replay packets from a pcap file instead of live capture.
    #[arg(long, conflicts_with = "iface")]
    pcap: Option<PathBuf>,

    /// Generate deterministic synthetic traffic instead of capturing
    /// (no root needed; exercises the full pipeline for demos/tests).
    #[arg(long, conflicts_with_all = ["iface", "pcap"])]
    sim: bool,

    /// Seed for --sim synthetic traffic.
    #[arg(long)]
    seed: Option<u64>,

    /// Target packets per second for --sim synthetic traffic (0 = flat out).
    #[arg(long)]
    pps: Option<u32>,

    /// List available interfaces and exit.
    #[arg(long)]
    list_ifaces: bool,

    /// Seconds between status lines.
    #[arg(long)]
    interval: Option<u64>,

    /// Stop after N packets (for testing).
    #[arg(long)]
    max_packets: Option<u64>,

    /// Enable promiscuous mode on the capture interface.
    #[arg(long, default_value_t = false)]
    promiscuous: bool,

    /// Write Zeek-style NDJSON events (conn/dns/ssl/http/heartbeat) under
    /// this directory, rotating files at --rotate-bytes. Opt-in: without
    /// it the sensor only prints counters.
    #[arg(long)]
    events: Option<PathBuf>,

    /// Rotate the NDJSON event file when it exceeds this many bytes
    /// (SD-card-friendly default).
    #[arg(long)]
    rotate_bytes: Option<u64>,
}

fn print_interfaces() {
    let ifaces = list_interfaces();
    if ifaces.is_empty() {
        println!("no interfaces found");
    } else {
        for name in &ifaces {
            println!("{name}");
        }
    }
}

fn print_status(counter: &mut LinkCounter) {
    let pps = counter.pps_since();
    let s = counter.snapshot();
    println!(
        "{} total={} pps={:.1} bytes={} ipv4={} ipv6={} arp={} other={}",
        now_iso8601(),
        s.total_frames,
        pps,
        s.bytes,
        s.ipv4,
        s.ipv6,
        s.arp,
        s.other
    );
}

fn print_summary(counter: &LinkCounter) {
    let s = counter.snapshot();
    println!(
        "{} summary total={} bytes={} ipv4={} ipv6={} arp={} other={}",
        now_iso8601(),
        s.total_frames,
        s.bytes,
        s.ipv4,
        s.ipv6,
        s.arp,
        s.other
    );
}

fn run() -> Result<()> {
    let args = Args::parse();

    if args.list_ifaces {
        print_interfaces();
        return Ok(());
    }

    // Optional config file; every value is optional and flags win.
    let config = match &args.config {
        Some(path) => {
            Some(sensor::config::SensorConfig::load(path).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
        None => None,
    };
    let cfg = config.as_ref();
    let sim = args.sim || cfg.and_then(|c| c.sensor.sim).unwrap_or(false);
    let iface = args
        .iface
        .clone()
        .or_else(|| cfg.and_then(|c| c.sensor.iface.clone()));
    let pcap: Option<PathBuf> = args
        .pcap
        .clone()
        .or_else(|| cfg.and_then(|c| c.sensor.pcap.clone()).map(PathBuf::from));
    let promiscuous = args.promiscuous || cfg.and_then(|c| c.sensor.promiscuous).unwrap_or(false);
    let seed = args.seed.or(cfg.and_then(|c| c.sensor.seed)).unwrap_or(42);
    let pps = args.pps.or(cfg.and_then(|c| c.sensor.pps)).unwrap_or(240);
    let interval = args
        .interval
        .or(cfg.and_then(|c| c.sensor.interval))
        .unwrap_or(2);
    let rotate_bytes = args
        .rotate_bytes
        .or(cfg.and_then(|c| c.sensor.rotate_bytes))
        .unwrap_or(16 * 1024 * 1024);
    let events = args
        .events
        .clone()
        .or_else(|| cfg.and_then(|c| c.sensor.events.clone()).map(PathBuf::from));

    if interval == 0 {
        bail!("--interval must be >= 1");
    }

    let mut source_count = 0;
    if sim {
        source_count += 1;
    }
    if pcap.is_some() {
        source_count += 1;
    }
    if iface.is_some() {
        source_count += 1;
    }
    if source_count > 1 {
        // CLI + config may both name a source; pick in the documented
        // precedence order rather than failing.
        tracing::warn!(
            "multiple capture sources set (config + flags); precedence: sim, then pcap, then iface"
        );
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    ctrlc::set_handler(move || {
        flag.store(true, Ordering::SeqCst);
    })
    .context("failed to install Ctrl-C handler")?;

    // Build the packet source: sim generation, pcap replay, or live capture.
    let source: Box<dyn PacketSource<Item = SourceItem> + Send> = if sim {
        if promiscuous {
            tracing::info!("--promiscuous has no effect in --sim mode");
        }
        tracing::info!(seed, pps, "simulating traffic");
        Box::new(SimSource::new(seed, pps))
    } else if let Some(path) = &pcap {
        if promiscuous {
            tracing::info!("--promiscuous has no effect in --pcap mode");
        }
        tracing::info!(pcap = %path.display(), "replaying pcap");
        Box::new(
            PcapSource::open(path)
                .with_context(|| format!("failed to open pcap '{}'", path.display()))?,
        )
    } else {
        let Some(iface_name) = iface.clone() else {
            print_interfaces();
            println!(
                "hint: pass --iface <NAME> to capture, --sim for synthetic traffic, or --list-ifaces to list"
            );
            return Ok(());
        };
        tracing::info!(iface = %iface_name, "capturing");
        Box::new(DatalinkSource::open(&iface_name, promiscuous)?)
    };

    // Reader thread owns the source and pushes (bytes, timestamp, wire len)
    // over an unbounded channel as fast as the source yields them. The main
    // loop below uses `recv_timeout` so status/heartbeat lines fire on
    // wall-clock intervals even with zero traffic (fixing the old
    // blocking-`rx.next()` idle starvation), leaving a hook for future
    // flow-expiry work.
    let (tx, rx) = std::sync::mpsc::channel::<SourceItem>();
    std::thread::spawn(move || {
        let mut src = source;
        while let Some(item) = src.next_packet() {
            if tx.send(item).is_err() {
                break;
            }
        }
    });

    let live_window_secs = cfg.and_then(|c| c.detect.live_window_secs).unwrap_or(600.0);
    let cooldown_secs = cfg.and_then(|c| c.detect.cooldown_secs).unwrap_or(300.0);
    let mut live = Some(LiveEngine::new(
        detect::RuleEngine::with_defaults(),
        live_window_secs,
        cooldown_secs,
    ));

    let mut notify = Dispatch::new();
    if let (Some(url), Some(topic)) = (
        cfg.and_then(|c| c.alert.ntfy_url.as_deref()),
        cfg.and_then(|c| c.alert.ntfy_topic.as_deref()),
    ) {
        notify.add(Channel::Ntfy(Ntfy::new(url, topic)));
    }
    let alert_cfg = cfg.map(|c| &c.alert);
    if let (Some(host), Some(user), Some(pass), Some(from), Some(to)) = (
        alert_cfg.and_then(|a| a.mail_host.as_deref()),
        alert_cfg.and_then(|a| a.mail_user.as_deref()),
        alert_cfg.and_then(|a| a.mail_pass.as_deref()),
        alert_cfg.and_then(|a| a.mail_from.as_deref()),
        alert_cfg.and_then(|a| a.mail_to.as_deref()),
    ) {
        notify.add(Channel::Mail(sensor::notify::SmtpMailer::new(
            host, user, pass, from, to,
        )));
    }
    let blind_secs = cfg.and_then(|c| c.alert.blind_secs).unwrap_or(600);

    let mut counter = LinkCounter::new();
    let mut pipeline = EventPipeline::new(Duration::from_secs(60), Duration::from_secs(3600));
    let retention = sensor::event::RetentionPolicy::new(
        cfg.and_then(|c| c.retention.max_dir_bytes),
        cfg.and_then(|c| c.retention.max_age_secs),
    );
    let mut sink = match &events {
        Some(dir) => Some(
            NdjsonSink::create_with_retention(dir, "events", rotate_bytes, retention)
                .with_context(|| format!("failed to create event sink in '{}'", dir.display()))?,
        ),
        None => None,
    };
    // Device inventory lives beside the events (retention only sweeps
    // *.ndjson, so devices.json is never collected).
    let inventory_path = events.as_ref().map(|dir| dir.join("devices.json"));
    let mut inventory = inventory_path
        .as_deref()
        .map(Inventory::load)
        .map(|(inv, err)| {
            if let Some(e) = err {
                tracing::warn!(error = %e, "inventory state unreadable; starting fresh");
            }
            inv
        })
        .unwrap_or_default();

    let tick = Duration::from_secs(interval);
    let mut deadline = Instant::now() + tick;
    let mut eof = false;
    let mut last_frame = Instant::now();
    let mut last_blind_alert = Option::<Instant>::None;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            tracing::info!("shutdown requested");
            break;
        }

        let timeout = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(timeout) {
            Ok(Ok(pkt)) => {
                last_frame = Instant::now();
                counter.record_frame(&pkt.data);
                let events =
                    pipeline.observe(pkt.timestamp, u64::from(pkt.original_len), &pkt.data);
                ingest(&mut live, &mut sink, &mut inventory, &notify, events)?;
                if let Some(max) = args.max_packets
                    && counter.snapshot().total_frames >= max
                {
                    break;
                }
                // Fast replay can lap the deadline without a timeout;
                // run the full housekeeping (status, expiry, live scan,
                // retention, self-watch) on wall-clock time so sustained
                // traffic never starves it.
                if Instant::now() >= deadline {
                    deadline = Instant::now() + tick;
                    housekeeping(
                        &mut counter,
                        &mut pipeline,
                        &mut live,
                        &mut sink,
                        &mut inventory,
                        &inventory_path,
                        &notify,
                        blind_secs,
                        &mut last_frame,
                        &mut last_blind_alert,
                    )?;
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "source read error");
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                deadline = Instant::now() + tick;
                housekeeping(
                    &mut counter,
                    &mut pipeline,
                    &mut live,
                    &mut sink,
                    &mut inventory,
                    &inventory_path,
                    &notify,
                    blind_secs,
                    &mut last_frame,
                    &mut last_blind_alert,
                )?;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eof = true;
                break;
            }
        }
    }

    print_summary(&counter);
    // Drain remaining flows and flush before any non-EOF exit: the sink's
    // BufWriter would not run its Drop on `process::exit` below.
    ingest(
        &mut live,
        &mut sink,
        &mut inventory,
        &notify,
        pipeline.finish(),
    )?;
    // Final scan: alerts still pending in the live window fire before exit.
    emit_alerts(&mut live, &mut sink, &notify, SystemTime::now())?;
    if let Some(path) = &inventory_path
        && let Err(e) = inventory.save(path)
    {
        tracing::warn!(error = %e, "inventory save failed");
    }
    if let Some(sink) = &mut sink {
        // The drain above can rotate past the cap; one last sweep keeps
        // the exit state bounded too.
        match sink.enforce_retention(SystemTime::now()) {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "retention swept event files"),
            Err(e) => tracing::warn!(error = %e, "retention sweep failed"),
        }
        sink.flush().context("failed to flush event sink")?;
        println!(
            "{} events dir={} files={} events={}",
            now_iso8601(),
            events
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new(""))
                .display(),
            sink.files_written(),
            sink.events_written()
        );
    }
    if !eof {
        // The reader thread may be blocked inside `pnet::datalink`'s
        // uninterruptible `next()`; joining it could hang shutdown
        // (Ctrl-C / max-packets) forever. It owns no resources needing
        // cleanup, so exit the process directly and let the OS reclaim it.
        std::process::exit(0);
    }
    Ok(())
}

/// Feed events to the live detection window and the event sink; either
/// side may be disabled, in which case it is skipped.
/// Wall-clock housekeeping shared by the idle and busy loop paths:
/// status line, flow expiry, heartbeat, live scan, inventory save,
/// retention sweep, and the blind self-watch.
#[allow(clippy::too_many_arguments)]
fn housekeeping(
    counter: &mut LinkCounter,
    pipeline: &mut EventPipeline,
    live: &mut Option<LiveEngine>,
    sink: &mut Option<NdjsonSink>,
    inventory: &mut Inventory,
    inventory_path: &Option<PathBuf>,
    notify: &Dispatch,
    blind_secs: u64,
    last_frame: &mut Instant,
    last_blind_alert: &mut Option<Instant>,
) -> Result<()> {
    print_status(counter);
    let now = SystemTime::now();
    ingest(live, sink, inventory, notify, pipeline.expire(now))?;
    ingest(live, sink, inventory, notify, vec![pipeline.heartbeat(now)])?;
    if let Some(sink) = sink {
        match sink.enforce_retention(now) {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "retention swept event files"),
            Err(e) => tracing::warn!(error = %e, "retention sweep failed"),
        }
    }
    emit_alerts(live, sink, notify, now)?;
    if let Some(path) = inventory_path
        && let Err(e) = inventory.save(path)
    {
        tracing::warn!(error = %e, "inventory save failed");
    }
    // Self-watch: a live sensor that sees zero frames for blind_secs is
    // probably unplugged or mis-mirrored; say so (pnet exposes no drop
    // counters, so blindness is the observable failure mode).
    let blind = last_frame.elapsed();
    if blind >= Duration::from_secs(blind_secs) {
        let due_again = last_blind_alert.is_none_or(|at| at.elapsed() >= Duration::from_secs(1800));
        if due_again {
            println!(
                "{} ALERT sensor-blind [high] -: zero frames for {}s",
                now_iso8601(),
                blind.as_secs()
            );
            let blind_alert = events::AlertEvent {
                uid: String::new(),
                ts: unix_ts(now),
                name: "sensor-blind".to_string(),
                severity: events::Severity::High,
                src: "sensor".to_string(),
                dst: None,
                message: format!("zero frames for {}s", blind.as_secs()),
                evidence: vec![],
            };
            if let Some(sink) = sink {
                sink.write(&Event::Alert(blind_alert.clone()))
                    .context("failed to write alert to NDJSON sink")?;
            }
            for e in notify.publish(&blind_alert) {
                tracing::warn!(error = %e, "blind-watch push failed");
            }
            *last_blind_alert = Some(Instant::now());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ingest(
    live: &mut Option<LiveEngine>,
    sink: &mut Option<NdjsonSink>,
    inventory: &mut Inventory,
    notify: &Dispatch,
    events: Vec<Event>,
) -> Result<()> {
    for event in &events {
        if let Some(live) = live {
            live.push(event);
        }
        if let Some(alert) = inventory.observe(event) {
            println!(
                "{} ALERT {} [{}] {}: {}",
                now_iso8601(),
                alert.name,
                format!("{:?}", alert.severity).to_lowercase(),
                alert.src,
                alert.message
            );
            if let Some(sink) = sink {
                sink.write(&Event::Alert(alert.clone()))
                    .context("failed to write alert to NDJSON sink")?;
            }
            for e in notify.publish(&alert) {
                tracing::warn!(error = %e, "new-device delivery failed");
            }
        }
        if let Some(sink) = sink {
            sink.write(event)
                .context("failed to write event to NDJSON sink")?;
        }
    }
    Ok(())
}

/// Run the live engine and emit any alerts that fired: one stdout line
/// each (always) plus an Alert event in the sink when configured.
fn emit_alerts(
    live: &mut Option<LiveEngine>,
    sink: &mut Option<NdjsonSink>,
    notify: &Dispatch,
    now: SystemTime,
) -> Result<()> {
    let Some(live) = live else {
        return Ok(());
    };
    for alert in live.tick(unix_ts(now)) {
        println!(
            "{} ALERT {} [{}] {} -> {}: {}",
            now_iso8601(),
            alert.name,
            format!("{:?}", alert.severity).to_lowercase(),
            alert.src,
            alert.dst.as_deref().unwrap_or("-"),
            alert.message
        );
        if let Some(sink) = sink {
            sink.write(&Event::Alert(alert.clone()))
                .context("failed to write alert to NDJSON sink")?;
        }
        // Best-effort push: never let delivery break capture.
        for e in notify.publish(&alert) {
            tracing::warn!(error = %e, name = %alert.name, "alert delivery failed");
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    run()
}
