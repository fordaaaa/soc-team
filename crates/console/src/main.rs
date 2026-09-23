//! `socteam-console` — live packet stats over HTTP/WS.
//!
//! Owns a [`PacketSource`] in a background reader thread and serves the
//! rolling [`Snapshot`] via Axum.

use anyhow::{Context, Result, bail};
use clap::Parser;
use console::{SnapshotCollector, router};
use sensor::source::{DatalinkSource, PacketSource, PcapSource, SimSource, SourceItem};
use std::path::PathBuf;
use std::time::Duration;

/// Live console for socteam sensor counters.
#[derive(Debug, Parser)]
#[command(name = "socteam-console", version, about = "socteam live console")]
struct Cli {
    /// Interface to capture on (e.g. en0, eth0).
    #[arg(long)]
    iface: Option<String>,

    /// Replay packets from a pcap file instead of live capture.
    #[arg(long, conflicts_with = "iface")]
    pcap: Option<PathBuf>,

    /// Generate deterministic synthetic traffic (no root needed).
    #[arg(long, conflicts_with_all = ["iface", "pcap"])]
    simulate: bool,

    /// Address to bind the HTTP server to.
    ///
    /// SECURITY: loopback-only default is deliberate — no auth yet;
    /// do not expose without an auth story.
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,

    /// Milliseconds between snapshot publishes.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,

    /// Stop after N packets (for testing).
    #[arg(long)]
    max_packets: Option<u64>,

    /// Seed for deterministic synthetic traffic (sim only).
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Target packets per second for synthetic traffic (sim only).
    #[arg(long, default_value_t = 240)]
    pps: u32,

    /// Do not open the console in the default browser after start.
    ///
    /// Auto-open is best-effort: on headless hosts (e.g. a Pi over SSH)
    /// the attempt fails softly and is logged; the URL is always printed.
    #[arg(long)]
    no_open: bool,
}

/// Best-effort open of `url` in the default browser.
///
/// Never fatal: a missing opener (headless host) or a failed spawn is
/// logged and the caller's stdout URL remains the fallback.
fn open_browser(url: &str) {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    match std::process::Command::new(program).arg(url).spawn() {
        Ok(child) => {
            tracing::debug!(pid = child.id(), url, "opened browser");
        }
        Err(e) => {
            tracing::info!(error = %e, url, "browser not opened (headless host?); use the URL above");
        }
    }
}

async fn run() -> Result<()> {
    let args = Cli::parse();

    if args.interval_ms == 0 {
        bail!("--interval-ms must be >= 1");
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))?;

    let source: Box<dyn PacketSource<Item = SourceItem> + Send>;
    let kind: &'static str;
    if args.simulate {
        tracing::info!(seed = args.seed, pps = args.pps, "simulating traffic");
        source = Box::new(SimSource::new(args.seed, args.pps));
        kind = "sim";
    } else if let Some(path) = &args.pcap {
        tracing::info!(pcap = %path.display(), "replaying pcap");
        source = Box::new(
            PcapSource::open(path)
                .with_context(|| format!("failed to open pcap '{}'", path.display()))?,
        );
        kind = "pcap";
    } else if let Some(iface_name) = &args.iface {
        tracing::info!(iface = %iface_name, "capturing");
        source = Box::new(DatalinkSource::open(iface_name, false)?);
        kind = "live";
    } else {
        bail!("exactly one of --iface, --pcap, --simulate is required");
    }

    let interval = Duration::from_millis(args.interval_ms);
    let collector = SnapshotCollector::spawn(source, kind, interval);

    if let Some(max) = args.max_packets {
        let watcher = std::sync::Arc::clone(&collector);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let done = watcher
                    .snapshot()
                    .is_some_and(|snap| snap.total_frames >= max);
                if done {
                    // The reader thread may be blocked inside
                    // `pnet::datalink`'s uninterruptible `next()`; joining
                    // it could hang shutdown forever. It owns no resources
                    // needing cleanup, so exit the process directly and let
                    // the OS reclaim it.
                    std::process::exit(0);
                }
            }
        });
    }

    let app = router(std::sync::Arc::clone(&collector));
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind '{}'", args.bind))?;
    println!(
        "socteam-console listening on http://{} (source: {kind})",
        args.bind
    );
    if !args.no_open {
        open_browser(&format!("http://{}", args.bind));
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::warn!(error = %e, "ctrl-c watch failed");
            }
        })
        .await
        .context("console server failed")?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}
