//! NDJSON event sink with size-based rotation.
//!
//! One JSON object per line; files rotate to `{prefix}-{unix_millis}-{seq:04}.ndjson`
//! before a line would push the current file past `max_bytes`. A single line
//! larger than `max_bytes` is allowed to occupy a file alone (documented).

use super::Event;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct NdjsonSink {
    dir: PathBuf,
    prefix: String,
    max_bytes: u64,
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

impl NdjsonSink {
    /// Create the directory (create_dir_all) and open the first file.
    pub fn create(dir: impl AsRef<Path>, prefix: &str, max_bytes: u64) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let seq: u64 = 1;
        let path = dir.join(format!("{}-{}-{:04}.ndjson", prefix, now_millis(), seq));
        let file = File::create(&path)?;
        Ok(Self {
            dir,
            prefix: prefix.to_string(),
            max_bytes,
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
}
