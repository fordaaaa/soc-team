//! `socteam-sensor` — Phase 0 skeleton binary.
//!
//! Opens an interface via `pnet::datalink` and prints per-interval frame
//! counters to stdout.
//!
//! Phase 1 replaces the datalink backend on Linux with AF_PACKET rings +
//! eBPF filtering for zero-copy/low latency.

use anyhow::{Context, Result, bail};
use clap::Parser;
use pnet::datalink::{Channel, Config};
use sensor::{count::LinkCounter, iface::list_interfaces};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Local-network security sensor (Phase 0 skeleton).
#[derive(Debug, Parser)]
#[command(name = "socteam-sensor", version, about = "socteam sensor skeleton")]
struct Args {
    /// Interface to capture on (e.g. en0, eth0).
    #[arg(long)]
    iface: Option<String>,

    /// List available interfaces and exit.
    #[arg(long)]
    list_ifaces: bool,

    /// Seconds between status lines.
    #[arg(long, default_value_t = 2)]
    interval: u64,

    /// Stop after N packets (for testing).
    #[arg(long)]
    max_packets: Option<u64>,

    /// Enable promiscuous mode on the capture interface.
    #[arg(long, default_value_t = false)]
    promiscuous: bool,
}

/// Current UTC time as an ISO-8601 string (`YYYY-MM-DDTHH:MM:SSZ`).
fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_unix_secs(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Convert unix seconds to (year, month, day, hour, min, sec) in UTC
/// (Howard Hinnant's days-from-civil algorithm, pure std).
fn civil_from_unix_secs(secs: u64) -> (i64, u64, u64, u64, u64, u64) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    (
        y,
        m as u64,
        d as u64,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
    )
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

fn run() -> Result<()> {
    let args = Args::parse();

    if args.list_ifaces {
        print_interfaces();
        return Ok(());
    }

    let Some(iface_name) = args.iface.clone() else {
        print_interfaces();
        println!("hint: pass --iface <NAME> to capture, or --list-ifaces to list");
        return Ok(());
    };

    if args.interval == 0 {
        bail!("--interval must be >= 1");
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

    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .with_context(|| format!("interface '{iface_name}' not found"))?;

    let config = Config {
        promiscuous: args.promiscuous,
        ..Config::default()
    };
    let mut rx = match pnet::datalink::channel(&interface, config)
        .context("failed to open datalink channel (try running with sudo)")?
    {
        Channel::Ethernet(_, rx) => rx,
        _ => bail!("unsupported channel type for interface '{iface_name}'"),
    };

    tracing::info!(iface = %iface_name, "capturing");

    let mut counter = LinkCounter::new();
    let interval = Duration::from_secs(args.interval);
    let mut deadline = Instant::now() + interval;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            tracing::info!("shutdown requested");
            break;
        }

        match rx.next() {
            Ok(frame) => {
                counter.record_frame(frame);
            }
            Err(e) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                tracing::warn!(error = %e, "read error");
                continue;
            }
        }

        if let Some(max) = args.max_packets
            && counter.snapshot().total_frames >= max
        {
            break;
        }

        if Instant::now() >= deadline {
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
            deadline = Instant::now() + interval;
        }
    }

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
    Ok(())
}

fn main() -> Result<()> {
    run()
}
