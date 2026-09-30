//! NDJSON event sink with size-based rotation and directory retention.
//!
//! One JSON object per line; files rotate to `{prefix}-{unix_millis}-{seq:04}.ndjson`
//! before a line would push the current file past `max_bytes`. A single line
//! larger than `max_bytes` is allowed to occupy a file alone (documented).
//! An optional [`RetentionPolicy`] keeps the whole directory bounded by
//! total bytes and/or file age — SD cards should never fill silently.

use super::Event;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Directory-level retention caps for rotated event files.
#[derive(Debug, Clone, Copy, Default)]
pub struct RetentionPolicy {
    /// Delete oldest rotated files while the directory exceeds this many bytes.
    pub max_dir_bytes: Option<u64>,
    /// Delete rotated files whose modified time is older than this many seconds.
    pub max_age_secs: Option<u64>,
}

impl RetentionPolicy {
    /// Build a policy, or `None` when both caps are unset.
    pub fn new(max_dir_bytes: Option<u64>, max_age_secs: Option<u64>) -> Option<Self> {
        if max_dir_bytes.is_none() && max_age_secs.is_none() {
            None
        } else {
            Some(Self {
                max_dir_bytes,
                max_age_secs,
            })
        }
    }
}

pub struct NdjsonSink {
    dir: PathBuf,
    prefix: String,
    max_bytes: u64,
    retention: Option<RetentionPolicy>,
    writer: BufWriter<File>,
    path: PathBuf,
    written: u64, // bytes in the CURRENT file
    files_written: u64,
    events_written: u64,
}

/// Milliseconds since the Unix epoch as u64, saturating; pre-epoch clocks map to 0.
fn now_millis() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

/// Seconds since the Unix epoch as u64, saturating.
fn unix_secs(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl NdjsonSink {
    /// Create the directory (create_dir_all) and open the first file.
    pub fn create(dir: impl AsRef<Path>, prefix: &str, max_bytes: u64) -> io::Result<Self> {
        Self::create_with_retention(dir, prefix, max_bytes, None)
    }

    /// Like [`create`](Self::create), with directory retention caps.
    pub fn create_with_retention(
        dir: impl AsRef<Path>,
        prefix: &str,
        max_bytes: u64,
        retention: Option<RetentionPolicy>,
    ) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let seq: u64 = 1;
        let path = dir.join(format!("{}-{}-{:04}.ndjson", prefix, now_millis(), seq));
        let file = File::create(&path)?;
        Ok(Self {
            dir,
            prefix: prefix.to_string(),
            max_bytes,
            retention,
            writer: BufWriter::new(file),
            path,
            written: 0,
            files_written: 1,
            events_written: 0,
        })
    }

    /// Open a fresh file: creates the dir/named file, resets `written` to 0,
    /// and increments `files_written`.
    fn open_new(&mut self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        self.files_written += 1;
        let path = self.dir.join(format!(
            "{}-{}-{:04}.ndjson",
            self.prefix,
            now_millis(),
            self.files_written
        ));
        let file = File::create(&path)?;
        self.writer = BufWriter::new(file);
        self.path = path;
        self.written = 0;
        Ok(())
    }

    /// Serialize `event` and append it as one NDJSON line, rotating first
    /// when `written > 0 && written + line.len() as u64 > max_bytes`.
    /// serde_json errors map to io::ErrorKind::InvalidData.
    pub fn write(&mut self, event: &Event) -> io::Result<()> {
        let mut line = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        if self.written > 0 && self.written + line.len() as u64 > self.max_bytes {
            self.open_new()?;
        }
        self.writer.write_all(line.as_bytes())?;
        self.written += line.len() as u64;
        self.events_written += 1;
        Ok(())
    }

    /// Flush the buffered writer (call at shutdown / test boundaries).
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Enforce the retention policy against the events directory: delete
    /// rotated files (never the one currently being written) older than
    /// the age cap, then — while still over the byte cap — oldest first.
    /// `now` is injected for testability. Returns the deleted-file count.
    /// Individual delete failures are logged and skipped: retention must
    /// never take the sink down.
    pub fn enforce_retention(&mut self, now: SystemTime) -> io::Result<usize> {
        let Some(policy) = self.retention else {
            return Ok(0);
        };
        let now_secs = unix_secs(now);
        // path, size, mtime secs — rotated files only.
        let mut candidates: Vec<(PathBuf, u64, u64)> = Vec::new();
        for entry in fs::read_dir(&self.dir)?.flatten() {
            let path = entry.path();
            if path == self.path || !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with(self.prefix.as_str()) || !name.ends_with(".ndjson") {
                continue;
            }
            let meta = entry.metadata()?;
            let mtime_secs = meta
                .modified()
                .ok()
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            candidates.push((path, meta.len(), mtime_secs));
        }

        let mut deleted = 0usize;
        if let Some(max_age) = policy.max_age_secs {
            candidates.retain(|(path, _, mtime)| {
                let expired = now_secs.saturating_sub(*mtime) > max_age;
                if expired && fs::remove_file(path).is_ok() {
                    deleted += 1;
                }
                !expired
            });
        }
        if let Some(max_bytes) = policy.max_dir_bytes {
            // Name order is chronological (unix_millis + zero-padded seq).
            candidates.sort_by(|a, b| a.0.cmp(&b.0));
            let mut total: u64 =
                candidates.iter().map(|(_, size, _)| size).sum::<u64>() + self.written;
            for (path, size, _) in &candidates {
                if total <= max_bytes {
                    break;
                }
                if fs::remove_file(path).is_ok() {
                    deleted += 1;
                    total = total.saturating_sub(*size);
                } else {
                    break;
                }
            }
        }
        Ok(deleted)
    }

    /// Path of the file currently being written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Files created so far (≥ 1).
    pub fn files_written(&self) -> u64 {
        self.files_written
    }

    /// Events written since creation.
    pub fn events_written(&self) -> u64 {
        self.events_written
    }
}

impl Drop for NdjsonSink {
    fn drop(&mut self) {
        let _ = self.writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, HeartbeatEvent};
    use std::time::Duration;

    fn hb(ts: f64) -> Event {
        Event::Heartbeat(HeartbeatEvent {
            ts,
            total_frames: 1,
            bytes: 1,
            active_flows: 0,
            events_emitted: 0,
        })
    }

    fn sink_files_sorted(dir: &Path, prefix: &str) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(prefix) && n.ends_with(".ndjson"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        files
    }

    #[test]
    fn rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = NdjsonSink::create(tmp.path(), "events", 60).unwrap();
        for i in 1..=5 {
            sink.write(&hb(i as f64)).unwrap();
        }
        sink.flush().unwrap();

        assert!(sink.files_written() >= 2, "expected rotation, got 1 file");
        assert_eq!(sink.events_written(), 5);

        let files = sink_files_sorted(tmp.path(), "events");
        assert!(files.len() >= 2);

        let mut ts_order = Vec::new();
        for f in &files {
            let content = fs::read_to_string(f).unwrap();
            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
                    panic!("invalid JSON in {}: {e}\nline: {line}", f.display())
                });
                let ts = v.get("ts").and_then(|t| t.as_f64()).expect("missing ts");
                ts_order.push(ts);
            }
        }
        assert_eq!(ts_order, vec![1.0, 2.0, 3.0, 4.0, 5.0]);
    }

    #[test]
    fn no_rotation_under_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = NdjsonSink::create(tmp.path(), "events", 1_000_000).unwrap();
        for i in 1..=3 {
            sink.write(&hb(i as f64)).unwrap();
        }
        sink.flush().unwrap();

        assert_eq!(sink.files_written(), 1);
        assert_eq!(sink.events_written(), 3);
        let content = fs::read_to_string(sink.path()).unwrap();
        assert_eq!(content.lines().count(), 3);
    }

    #[test]
    fn dir_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("events").join("sub");
        assert!(!nested.exists());
        let mut sink = NdjsonSink::create(&nested, "events", 1_000_000).unwrap();
        sink.write(&hb(1.0)).unwrap();
        sink.flush().unwrap();

        assert!(nested.is_dir());
        assert!(sink.path().starts_with(&nested));
        assert!(sink.path().is_file());
    }

    #[test]
    fn oversize_line_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = NdjsonSink::create(tmp.path(), "events", 10).unwrap();
        sink.write(&hb(1.0)).unwrap();
        sink.flush().unwrap();

        assert_eq!(sink.files_written(), 1);
        assert_eq!(sink.events_written(), 1);
        let content = fs::read_to_string(sink.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].len() > 10);
        let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["ts"], 1.0);
    }

    fn dir_bytes(dir: &Path) -> u64 {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.metadata().unwrap().len())
            .sum()
    }

    #[test]
    fn retention_byte_cap_deletes_oldest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = RetentionPolicy::new(Some(250), None);
        let mut sink = NdjsonSink::create_with_retention(tmp.path(), "events", 60, policy).unwrap();
        for i in 1..=5 {
            sink.write(&hb(i as f64)).unwrap();
        }
        sink.flush().unwrap();
        assert!(sink.files_written() >= 4, "expected rotation");

        let before = sink_files_sorted(tmp.path(), "events");
        let deleted = sink.enforce_retention(SystemTime::now()).unwrap();
        assert!(deleted >= 1, "expected deletions");
        assert!(dir_bytes(tmp.path()) <= 250, "cap exceeded");
        // The current file always survives.
        assert!(sink.path().is_file());
        // Deletion is oldest-first: what remains is a chronological suffix
        // of what existed.
        let after = sink_files_sorted(tmp.path(), "events");
        assert_eq!(after, before[before.len() - after.len()..]);
    }

    #[test]
    fn retention_age_cap_deletes_old_files() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = RetentionPolicy::new(None, Some(86_400));
        let mut sink = NdjsonSink::create_with_retention(tmp.path(), "events", 60, policy).unwrap();
        sink.write(&hb(1.0)).unwrap();
        sink.flush().unwrap();
        let old_path = sink.path().to_path_buf();
        sink.write(&hb(2.0)).unwrap(); // force rotation
        sink.flush().unwrap();

        // Backdate the first file by 10 days.
        let old_time = SystemTime::now() - Duration::from_secs(10 * 86_400);
        File::options()
            .write(true)
            .open(&old_path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();

        let deleted = sink.enforce_retention(SystemTime::now()).unwrap();
        assert_eq!(deleted, 1);
        assert!(!old_path.exists(), "aged-out file should be deleted");
        assert!(sink.path().is_file(), "current file must survive");
    }

    #[test]
    fn retention_never_touches_current_file() {
        let tmp = tempfile::tempdir().unwrap();
        // Cap below even one file: everything rotated gets deleted, but the
        // writer keeps its current file.
        let policy = RetentionPolicy::new(Some(10), None);
        let mut sink = NdjsonSink::create_with_retention(tmp.path(), "events", 60, policy).unwrap();
        for i in 1..=4 {
            sink.write(&hb(i as f64)).unwrap();
        }
        sink.flush().unwrap();

        let current = sink.path().to_path_buf();
        sink.enforce_retention(SystemTime::now()).unwrap();
        assert!(current.is_file());
        let remaining = sink_files_sorted(tmp.path(), "events");
        assert_eq!(remaining, vec![current]);
    }

    #[test]
    fn retention_no_policy_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = NdjsonSink::create(tmp.path(), "events", 60).unwrap();
        for i in 1..=3 {
            sink.write(&hb(i as f64)).unwrap();
        }
        sink.flush().unwrap();
        let deleted = sink.enforce_retention(SystemTime::now()).unwrap();
        assert_eq!(deleted, 0);
        assert!(sink_files_sorted(tmp.path(), "events").len() >= 2);
    }
}
