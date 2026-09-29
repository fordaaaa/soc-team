//! `socteam` control CLI: query the sensor's event stream and summarize
//! sensor health from the NDJSON files it writes.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ctl::{format_flows, format_heartbeat, latest_heartbeat, parse_duration};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use store::{EventStore, FlowFilter, MemoryStore};

/// socteam control CLI.
#[derive(Debug, Parser)]
#[command(name = "socteam", version, about = "socteam control CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    },
    /// List conn (flow) events recorded under an events directory.
    Flows {
        /// Directory of NDJSON event files written by `--events`.
        #[arg(long)]
        events: PathBuf,
        /// Only flows newer than this duration (e.g. 30s, 10m, 1h).
        #[arg(long)]
        last: Option<String>,
        /// Only flows whose src or dst equals this address.
        #[arg(long)]
        host: Option<String>,
    },
    /// Follow NDJSON event files and print new lines as they appear.
    /// Ctrl-C simply kills the process (no cleanup needed).
    Tail {
        /// Directory of NDJSON event files to follow.
        dir: PathBuf,
    },
}

/// Unix-epoch seconds as f64 (millisecond resolution); pre-epoch → 0.0.
fn unix_ts(ts: SystemTime) -> f64 {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as f64 + f64::from(d.subsec_millis()) / 1000.0,
        Err(_) => 0.0,
    }
}

fn run_status(events: Option<&Path>) -> Result<()> {
    let Some(dir) = events else {
        println!("sensor status: pass --events <DIR> to summarize the latest heartbeat");
        return Ok(());
    };
    let mut store = MemoryStore::new();
    store::load_dir(&mut store, dir)
        .with_context(|| format!("failed to load events from '{}'", dir.display()))?;
    match latest_heartbeat(store.events()) {
        Some(h) => println!("{}", format_heartbeat(h)),
        None => println!("no heartbeat events found in {}", dir.display()),
    }
    Ok(())
}

fn run_flows(events: &Path, last: Option<&str>, host: Option<&str>) -> Result<()> {
    let since_ts = match last {
        Some(raw) => {
            let dur = parse_duration(raw)
                .with_context(|| format!("invalid --last value '{raw}' (use e.g. 30s, 10m, 1h)"))?;
            Some(unix_ts(
                SystemTime::now().checked_sub(dur).unwrap_or(UNIX_EPOCH),
            ))
        }
        None => None,
    };
    let filter = FlowFilter {
        since_ts,
        host: host.map(str::to_string),
    };
    let mut store = MemoryStore::new();
    store::load_dir(&mut store, events)
        .with_context(|| format!("failed to load events from '{}'", events.display()))?;
    let rows = store.query_flows(&filter)?;
    if rows.is_empty() {
        println!("no flows matched (--events {})", events.display());
    } else {
        println!("{}", format_flows(&rows));
    }
    Ok(())
}

/// Follow `dir`: poll every 500 ms, print each complete new NDJSON line.
/// Only stdout carries event lines (pipeable); diagnostics go to stderr.
/// Files that disappear or fail to open mid-follow are skipped for that
/// iteration — rotation never deletes files, so this is defensive only.
fn run_tail(dir: &Path) -> Result<()> {
    eprintln!("tailing {} (ctrl-c to stop)", dir.display());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // Byte offsets of fully-consumed complete lines, per file.
    let mut offsets: BTreeMap<PathBuf, u64> = BTreeMap::new();
    // Trailing bytes not yet newline-terminated, per file.
    let mut partials: BTreeMap<PathBuf, String> = BTreeMap::new();

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
            buffer.push_str(&String::from_utf8_lossy(&new_bytes));

            // Print every complete line; keep the un-terminated tail.
            // Offsets advance only over complete lines plus their
            // newlines, never over the partial remainder. Write errors
            // (e.g. a closed pipe) are ignored: tail has nothing to clean up.
            let consumed = match buffer.rfind('\n') {
                Some(idx) => {
                    let complete = buffer[..idx].to_string();
                    for line in complete.split('\n') {
                        if !line.is_empty() {
                            let _ = writeln!(out, "{line}");
                        }
                    }
                    let _ = out.flush();
                    let consumed = idx + 1;
                    buffer.drain(..consumed);
                    offset + consumed as u64
                }
                None => offset,
            };
            offsets.insert(path, consumed);
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => println!("socteam {}", env!("CARGO_PKG_VERSION")),
        Command::Status { events } => run_status(events.as_deref())?,
        Command::Flows { events, last, host } => {
            run_flows(&events, last.as_deref(), host.as_deref())?
        }
        Command::Tail { dir } => run_tail(&dir)?,
    }
    Ok(())
}
