//! `socteam` control CLI: query the sensor's event stream, run the
//! detection engine, and summarize sensor health from the NDJSON files
//! it writes.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ctl::demo;
use ctl::{
    drain_complete_lines, format_alerts, format_flows, format_heartbeat, latest_heartbeat,
    parse_duration, parse_severity,
};
use detect::{RuleEngine, SniWatchDetector};
use sensor::event::Event;
use std::collections::BTreeMap;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use store::{AlertFilter, EventStore, FlowFilter, MemoryStore};

/// socteam control CLI.
#[derive(Debug, Parser)]
#[command(name = "socteam", version, about = "socteam control CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Event store backend for query subcommands.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum StoreKind {
    /// Load NDJSON event files into memory per invocation.
    Memory,
    /// Query a DuckDB database file (needs the `duckdb` build feature).
    #[value(name = "duckdb")]
    DuckDb,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Print the workspace version.
    Version,
    /// Summarize sensor health from the latest heartbeat event.
    Status {
        /// Directory of NDJSON event files written by `--events`.
        #[arg(long)]
        events: Option<PathBuf>,
        /// Print the heartbeat as a JSON line.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// List conn (flow) events recorded under an events directory.
    Flows {
        /// Directory of NDJSON event files (memory store).
        #[arg(long)]
        events: Option<PathBuf>,
        /// Only flows newer than this duration (e.g. 30s, 10m, 1h).
        #[arg(long)]
        last: Option<String>,
        /// Only flows whose src or dst equals this address.
        #[arg(long)]
        host: Option<String>,
        /// Print one JSON object per flow.
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Event store backend.
        #[arg(long, value_enum, default_value = "memory")]
        store: StoreKind,
        /// Path to a DuckDB database file (with --store duckdb).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// List detection alerts recorded under an events directory.
    Alerts {
        /// Directory of NDJSON event files (memory store).
        #[arg(long)]
        events: Option<PathBuf>,
        /// Only alerts newer than this duration (e.g. 30s, 10m, 1h).
        #[arg(long)]
        last: Option<String>,
        /// Minimum severity to include (low < medium < high).
        #[arg(long)]
        min_severity: Option<String>,
        /// Print one JSON object per alert.
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Event store backend.
        #[arg(long, value_enum, default_value = "memory")]
        store: StoreKind,
        /// Path to a DuckDB database file (with --store duckdb).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Follow NDJSON event files and print new lines as they appear.
    /// Ctrl-C simply kills the process (no cleanup needed).
    Tail {
        /// Directory of NDJSON event files to follow.
        dir: PathBuf,
    },
    /// Run the default detection set over an events directory and
    /// write alert events as NDJSON.
    Detect {
        /// Directory of NDJSON event files written by the sensor.
        #[arg(long)]
        events: PathBuf,
        /// Output NDJSON file for alert events.
        #[arg(long)]
        out: PathBuf,
        /// Optional watchlist file for the SNI detection (one domain
        /// per line; '#' starts a comment).
        #[arg(long)]
        watchlist: Option<PathBuf>,
    },
    /// Load an NDJSON events directory into a DuckDB database.
    Import {
        /// Directory of NDJSON event files written by the sensor.
        #[arg(long)]
        events: PathBuf,
        /// DuckDB database file to create or append to.
        #[arg(long)]
        db: PathBuf,
    },
    /// Generate the deterministic demo scenario (baseline traffic plus
    /// one attack per built-in detection).
    Demo {
        /// Output directory for the demo events and watchlist.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Unix-epoch seconds as f64 (millisecond resolution); pre-epoch → 0.0.
fn unix_ts(ts: SystemTime) -> f64 {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as f64 + f64::from(d.subsec_millis()) / 1000.0,
        Err(_) => 0.0,
    }
}

/// Since-bound from a `--last` duration string.
fn since_from_last(last: Option<&str>) -> Result<Option<f64>> {
    match last {
        Some(raw) => {
            let dur = parse_duration(raw)
                .with_context(|| format!("invalid --last value '{raw}' (use e.g. 30s, 10m, 1h)"))?;
            Ok(Some(unix_ts(
                SystemTime::now().checked_sub(dur).unwrap_or(UNIX_EPOCH),
            )))
        }
        None => Ok(None),
    }
}

/// Open the query backend: memory (from an events dir) or DuckDB.
fn open_query_store(
    kind: StoreKind,
    events: Option<&Path>,
    db: Option<&Path>,
) -> Result<Box<dyn EventStore>> {
    match kind {
        StoreKind::Memory => {
            let dir = events
                .context("this subcommand needs --events <DIR> (or --store duckdb --db <FILE>)")?;
            let mut store = MemoryStore::new();
            store::load_dir(&mut store, dir)
                .with_context(|| format!("failed to load events from '{}'", dir.display()))?;
            Ok(Box::new(store))
        }
        StoreKind::DuckDb => {
            let db = db.context("--store duckdb requires --db <FILE>")?;
            #[cfg(feature = "duckdb")]
            {
                Ok(Box::new(store::DuckStore::open(db)?))
            }
            #[cfg(not(feature = "duckdb"))]
            {
                let _ = db;
                anyhow::bail!("duckdb support requires building with --features duckdb")
            }
        }
    }
}

fn run_status(events: Option<&Path>, json: bool) -> Result<()> {
    let Some(dir) = events else {
        println!("sensor status: pass --events <DIR> to summarize the latest heartbeat");
        return Ok(());
    };
    let mut store = MemoryStore::new();
    store::load_dir(&mut store, dir)
        .with_context(|| format!("failed to load events from '{}'", dir.display()))?;
    match latest_heartbeat(store.events()) {
        Some(h) if json => {
            println!("{}", serde_json::to_string(&Event::Heartbeat(h.clone()))?);
        }
        Some(h) => println!("{}", format_heartbeat(h)),
        None => println!("no heartbeat events found in {}", dir.display()),
    }
    Ok(())
}

fn run_flows(
    kind: StoreKind,
    events: Option<&Path>,
    db: Option<&Path>,
    last: Option<&str>,
    host: Option<&str>,
    json: bool,
) -> Result<()> {
    let filter = FlowFilter {
        since_ts: since_from_last(last)?,
        host: host.map(str::to_string),
    };
    let store = open_query_store(kind, events, db)?;
    let rows = store.query_flows(&filter)?;
    if rows.is_empty() {
        println!("no flows matched");
        return Ok(());
    }
    if json {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for row in &rows {
            serde_json::to_writer(&mut out, row)?;
            writeln!(out)?;
        }
        out.flush()?;
    } else {
        println!("{}", format_flows(&rows));
    }
    Ok(())
}

fn run_alerts(
    kind: StoreKind,
    events: Option<&Path>,
    db: Option<&Path>,
    last: Option<&str>,
    min_severity: Option<&str>,
    json: bool,
) -> Result<()> {
    let min_severity = match min_severity {
        Some(raw) => Some(parse_severity(raw).with_context(|| {
            format!("invalid --min-severity '{raw}' (use low, medium, or high)")
        })?),
        None => None,
    };
    let filter = AlertFilter {
        since_ts: since_from_last(last)?,
        name: None,
        min_severity,
    };
    let store = open_query_store(kind, events, db)?;
    let alerts = store.query_alerts(&filter)?;
    if alerts.is_empty() {
        println!("no alerts matched");
        return Ok(());
    }
    if json {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for alert in &alerts {
            serde_json::to_writer(&mut out, &Event::Alert(alert.clone()))?;
            writeln!(out)?;
        }
        out.flush()?;
    } else {
        println!("{}", format_alerts(&alerts));
    }
    Ok(())
}

/// Follow `dir`: poll every 500 ms, print each complete new NDJSON line.
/// Only stdout carries event lines (pipeable); diagnostics go to stderr.
/// File offsets are tracked in raw bytes so invalid UTF-8 in a payload
/// never desyncs the follower. Files that disappear or fail to open
/// mid-follow are skipped for that iteration — rotation never deletes
/// files, so this is defensive only.
fn run_tail(dir: &Path) -> Result<()> {
    eprintln!("tailing {} (ctrl-c to stop)", dir.display());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // Byte offsets of fully-consumed complete lines, per file.
    let mut offsets: BTreeMap<PathBuf, u64> = BTreeMap::new();
    // Trailing bytes not yet newline-terminated, per file.
    let mut partials: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();

    loop {
        let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
                .collect(),
            // Directory gone: nothing to do this round.
            Err(_) => Vec::new(),
        };
        files.sort();

        for path in files {
            let offset = *offsets.get(&path).unwrap_or(&0);
            let Ok(mut file) = std::fs::File::open(&path) else {
                continue;
            };
            if file.seek(SeekFrom::Start(offset)).is_err() {
                continue;
            }
            let mut new_bytes = Vec::new();
            if file.read_to_end(&mut new_bytes).is_err() {
                continue;
            }
            if new_bytes.is_empty() {
                continue;
            }
            let buffer = partials.entry(path.clone()).or_default();
            buffer.extend_from_slice(&new_bytes);
            let (lines, consumed) = drain_complete_lines(buffer);
            if !lines.is_empty() {
                // Write errors (e.g. a closed pipe) are ignored: tail has
                // nothing to clean up.
                for line in &lines {
                    let _ = writeln!(out, "{line}");
                }
                let _ = out.flush();
            }
            offsets.insert(path, offset + consumed as u64);
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn run_detect(events: &Path, out: &Path, watchlist: Option<&Path>) -> Result<()> {
    let mut store = MemoryStore::new();
    store::load_dir(&mut store, events)
        .with_context(|| format!("failed to load events from '{}'", events.display()))?;
    let mut engine = RuleEngine::with_defaults();
    if let Some(path) = watchlist {
        let domains = read_watchlist(path)?;
        engine.register(Box::new(SniWatchDetector::new(domains)));
    }
    let alerts = engine.run(store.events());
    let file = std::fs::File::create(out)
        .with_context(|| format!("failed to create '{}'", out.display()))?;
    let mut writer = BufWriter::new(file);
    for alert in &alerts {
        serde_json::to_writer(&mut writer, &Event::Alert(alert.clone()))?;
        writeln!(writer)?;
    }
    writer.flush()?;
    println!("{} alerts written to {}", alerts.len(), out.display());
    Ok(())
}

/// One domain per line; blank lines and '#' comments are skipped.
fn read_watchlist(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read watchlist '{}'", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn run_import(events: &Path, db: &Path) -> Result<()> {
    #[cfg(feature = "duckdb")]
    {
        let mut store = store::DuckStore::open(db)?;
        store::load_dir(&mut store, events)
            .with_context(|| format!("failed to load events from '{}'", events.display()))?;
        println!("imported {} events into {}", store.len()?, db.display());
        Ok(())
    }
    #[cfg(not(feature = "duckdb"))]
    {
        let _ = (events, db);
        anyhow::bail!("duckdb support requires building with --features duckdb")
    }
}

fn run_demo(out: &Path) -> Result<()> {
    let count = demo::generate(out)
        .with_context(|| format!("failed to write demo to '{}'", out.display()))?;
    println!(
        "wrote {count} events and watchlist.txt to {}",
        out.display()
    );
    println!(
        "next: socteam detect --events {} --out alerts.ndjson --watchlist {}/watchlist.txt",
        out.display(),
        out.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => println!("socteam {}", env!("CARGO_PKG_VERSION")),
        Command::Status { events, json } => run_status(events.as_deref(), json)?,
        Command::Flows {
            events,
            last,
            host,
            json,
            store,
            db,
        } => run_flows(
            store,
            events.as_deref(),
            db.as_deref(),
            last.as_deref(),
            host.as_deref(),
            json,
        )?,
        Command::Alerts {
            events,
            last,
            min_severity,
            json,
            store,
            db,
        } => run_alerts(
            store,
            events.as_deref(),
            db.as_deref(),
            last.as_deref(),
            min_severity.as_deref(),
            json,
        )?,
        Command::Tail { dir } => run_tail(&dir)?,
        Command::Detect {
            events,
            out,
            watchlist,
        } => run_detect(&events, &out, watchlist.as_deref())?,
        Command::Import { events, db } => run_import(&events, &db)?,
        Command::Demo { out } => run_demo(&out)?,
    }
    Ok(())
}
