//! `socteam-sensor` — Phase 0 skeleton binary.
//!
//! Opens an interface via `pnet::datalink` or replays a pcap file and
//! prints per-interval frame counters to stdout.
//!
//! Phase 1 replaces the datalink backend on Linux with AF_PACKET rings +
//! eBPF filtering for zero-copy/low latency.

use anyhow::{Context, Result, bail};
use clap::Parser;
use sensor::{
    count::LinkCounter,
    iface::list_interfaces,
    source::{DatalinkSource, PacketSource, PcapSource, SourceItem, now_iso8601},
};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Local-network security sensor (Phase 0 skeleton).
#[derive(Debug, Parser)]
#[command(name = "socteam-sensor", version, about = "socteam sensor skeleton")]
struct Args {
    /// Interface to capture on (e.g. en0, eth0).
    #[arg(long)]
    iface: Option<String>,

    /// Replay packets from a pcap file instead of live capture.
    #[arg(long, conflicts_with = "iface")]
    pcap: Option<PathBuf>,

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

    // Build the packet source: pcap replay or live capture.
    let source: Box<dyn PacketSource<Item = SourceItem> + Send> = if let Some(path) = &args.pcap {
        if args.promiscuous {
            tracing::info!("--promiscuous has no effect in --pcap mode");
        }
        tracing::info!(pcap = %path.display(), "replaying pcap");
        Box::new(
            PcapSource::open(path)
                .with_context(|| format!("failed to open pcap '{}'", path.display()))?,
        )
    } else {
        let Some(iface_name) = args.iface.clone() else {
            print_interfaces();
            println!("hint: pass --iface <NAME> to capture, or --list-ifaces to list");
            return Ok(());
        };
        tracing::info!(iface = %iface_name, "capturing");
        Box::new(DatalinkSource::open(&iface_name, args.promiscuous)?)
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

    let mut counter = LinkCounter::new();
    let interval = Duration::from_secs(args.interval);
    let mut deadline = Instant::now() + interval;
    let mut eof = false;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            tracing::info!("shutdown requested");
            break;
        }

        let timeout = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(timeout) {
            Ok(Ok(pkt)) => {
                counter.record_frame(&pkt.data);
                if let Some(max) = args.max_packets
                    && counter.snapshot().total_frames >= max
                {
                    break;
                }
                // Fast replay can lap the deadline without a timeout; emit
                // wall-clock status lines so long pcaps still report.
                if Instant::now() >= deadline {
                    print_status(&mut counter);
                    deadline = Instant::now() + interval;
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "source read error");
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                print_status(&mut counter);
                deadline = Instant::now() + interval;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eof = true;
                break;
            }
        }
    }

    print_summary(&counter);
    if !eof {
        // The reader thread may be blocked inside `pnet::datalink`'s
        // uninterruptible `next()`; joining it could hang shutdown
        // (Ctrl-C / max-packets) forever. It owns no resources needing
        // cleanup, so exit the process directly and let the OS reclaim it.
        std::process::exit(0);
    }
    Ok(())
}

fn main() -> Result<()> {
    run()
}
