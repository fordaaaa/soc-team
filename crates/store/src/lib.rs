//! Event store: the queryable seam between the sensor's NDJSON event
//! stream and the operator.
//!
//! v0 ships an in-memory backend ([`MemoryStore`]) fed from NDJSON files
//! via [`load_file`]/[`load_dir`]; a persistent DuckDB backend is
//! available behind the default-off `duckdb` feature (see
//! [`duckdb::DuckStore`]).

use sensor::event::{AlertEvent, ConnEvent, Event, Severity};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// DuckDB-backed [`EventStore`] (requires the default-off `duckdb`
/// feature; the crate vendors the full C++ engine).
#[cfg(feature = "duckdb")]
pub mod duckdb;

#[cfg(feature = "duckdb")]
pub use duckdb::DuckStore;

/// Errors from store operations: I/O while reading event files, or a
/// line that does not deserialize as an [`Event`].
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Underlying filesystem error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// An NDJSON line failed to parse as an event.
    #[error("{path}:{line}: invalid event: {message}")]
    Serde {
        /// File containing the bad line.
        path: PathBuf,
        /// 1-based line number within the file.
        line: usize,
        /// Serde error description.
        message: String,
    },
    /// An event failed to (de)serialize.
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// Underlying DuckDB error (only with the `duckdb` feature).
    #[cfg(feature = "duckdb")]
    #[error("duckdb error: {0}")]
    Duck(#[from] ::duckdb::Error),
}

/// Filter for flow queries.
#[derive(Debug, Clone, Default)]
pub struct FlowFilter {
    /// Unix-epoch seconds lower bound (inclusive); `None` = no bound.
    pub since_ts: Option<f64>,
    /// Exact match against conn `src` OR `dst`; `None` = any host.
    pub host: Option<String>,
}

/// Filter for alert queries.
#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    /// Unix-epoch seconds lower bound (inclusive); `None` = no bound.
    pub since_ts: Option<f64>,
    /// Exact match against the detection name; `None` = any detection.
    pub name: Option<String>,
    /// Minimum severity (inclusive); `None` = any severity.
    pub min_severity: Option<Severity>,
}

/// One queried connection summary (a [`ConnEvent`] projection).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FlowRow {
    /// Unique event id.
    pub uid: String,
    /// Flow start, unix-epoch seconds.
    pub ts: f64,
    /// Connection duration in seconds.
    pub duration: f64,
    /// Human protocol name.
    pub proto: String,
    /// Connection state label (e.g. "SF").
    pub conn_state: String,
    /// Why the flow record was emitted (e.g. "fin").
    pub end_reason: String,
    /// Source IP address.
    pub src: String,
    /// Destination IP address.
    pub dst: String,
    /// Source port; `None` for portless protocols.
    pub src_port: Option<u16>,
    /// Destination port; `None` for portless protocols.
    pub dst_port: Option<u16>,
    /// Packet count in the `a → b` direction.
    pub pkts_a_to_b: u64,
    /// Byte count in the `a → b` direction.
    pub bytes_a_to_b: u64,
    /// Packet count in the `b → a` direction.
    pub pkts_b_to_a: u64,
    /// Byte count in the `b → a` direction.
    pub bytes_b_to_a: u64,
}

impl FlowRow {
    /// Project a conn event into a query row (plain field copies).
    pub fn from_conn(c: &ConnEvent) -> Self {
        Self {
            uid: c.uid.clone(),
            ts: c.ts,
            duration: c.duration,
            proto: c.proto.clone(),
            conn_state: c.conn_state.clone(),
            end_reason: c.end_reason.clone(),
            src: c.src.clone(),
            dst: c.dst.clone(),
            src_port: c.src_port,
            dst_port: c.dst_port,
            pkts_a_to_b: c.pkts_a_to_b,
            bytes_a_to_b: c.bytes_a_to_b,
            pkts_b_to_a: c.pkts_b_to_a,
            bytes_b_to_a: c.bytes_b_to_a,
        }
    }
}

/// A store of sensor events, queried as flows.
pub trait EventStore: Send {
    /// Append one event.
    fn append(&mut self, event: &Event) -> Result<(), StoreError>;

    /// Append every event in order (default: loop [`append`](Self::append)).
    fn append_all(&mut self, events: &[Event]) -> Result<(), StoreError> {
        for event in events {
            self.append(event)?;
        }
        Ok(())
    }

    /// Conn events passing `filter`, in append order.
    fn query_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowRow>, StoreError>;

    /// Alert events passing `filter`, in append order.
    fn query_alerts(&self, filter: &AlertFilter) -> Result<Vec<AlertEvent>, StoreError>;

    /// Total events stored (all kinds).
    fn len(&self) -> Result<usize, StoreError>;

    /// True when no events are stored.
    fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }
}

/// In-memory [`EventStore`]: appends keep every event, queries filter them.
pub struct MemoryStore {
    events: Vec<Event>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// All stored events in append order (used e.g. to find the latest
    /// heartbeat for a status line).
    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore for MemoryStore {
    fn append(&mut self, event: &Event) -> Result<(), StoreError> {
        self.events.push(event.clone());
        Ok(())
    }

    fn query_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowRow>, StoreError> {
        let rows: Vec<FlowRow> = self
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Conn(c) => {
                    let since_ok = filter.since_ts.is_none_or(|since| c.ts >= since);
                    let host_ok = filter
                        .host
                        .as_ref()
                        .is_none_or(|host| host == &c.src || host == &c.dst);
                    (since_ok && host_ok).then(|| FlowRow::from_conn(c))
                }
                _ => None,
            })
            .collect();
        Ok(rows)
    }

    fn query_alerts(&self, filter: &AlertFilter) -> Result<Vec<AlertEvent>, StoreError> {
        let alerts: Vec<AlertEvent> = self
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Alert(a) => {
                    let since_ok = filter.since_ts.is_none_or(|since| a.ts >= since);
                    let name_ok = filter.name.as_ref().is_none_or(|name| name == &a.name);
                    let sev_ok = filter.min_severity.is_none_or(|min| a.severity >= min);
                    (since_ok && name_ok && sev_ok).then(|| a.clone())
                }
                _ => None,
            })
            .collect();
        Ok(alerts)
    }

    fn len(&self) -> Result<usize, StoreError> {
        Ok(self.events.len())
    }
}

/// Load one NDJSON event file into `store`, skipping blank lines. A line
/// that fails to deserialize reports the file and line number.
pub fn load_file(store: &mut impl EventStore, path: &Path) -> Result<(), StoreError> {
    let file = fs::File::open(path)?;
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(trimmed).map_err(|e| StoreError::Serde {
            path: path.to_path_buf(),
            line: idx + 1,
            message: e.to_string(),
        })?;
        store.append(&event)?;
    }
    Ok(())
}

/// Load every `*.ndjson` file under `dir` into `store`, sorted by path:
/// the sink names files `{prefix}-{unix_millis}-{seq:04}.ndjson`, so path
/// order is chronological. A missing directory surfaces as [`StoreError::Io`].
pub fn load_dir(store: &mut impl EventStore, dir: &Path) -> Result<(), StoreError> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "ndjson"))
        .collect();
    paths.sort();
    for path in &paths {
        load_file(store, path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensor::event::{AlertEvent, DnsEvent, Severity};
    use std::io::Write;

    /// Synthetic conn event with fully explicit fields.
    fn conn(uid: &str, ts: f64, src: &str, dst: &str) -> Event {
        Event::Conn(ConnEvent {
            uid: uid.to_string(),
            ts,
            duration: 1.5,
            proto: "tcp".to_string(),
            conn_state: "SF".to_string(),
            end_reason: "fin".to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            src_port: Some(1234),
            dst_port: Some(80),
            pkts_a_to_b: 5,
            bytes_a_to_b: 600,
            pkts_b_to_a: 4,
            bytes_b_to_a: 500,
        })
    }

    /// Synthetic dns event with fully explicit fields.
    fn dns(uid: &str) -> Event {
        Event::Dns(DnsEvent {
            uid: uid.to_string(),
            ts: 200.0,
            src: "192.0.2.10".to_string(),
            dst: "198.51.100.7".to_string(),
            src_port: 5353,
            dst_port: 53,
            txid: 0x1234,
            is_response: false,
            rcode: 0,
            query: Some("example.com.".to_string()),
            qtype: Some(1),
            answers: vec![],
        })
    }

    #[test]
    fn append_then_query_roundtrip() {
        let mut store = MemoryStore::new();
        let events = vec![
            conn("conn1", 100.0, "192.0.2.10", "198.51.100.7"),
            conn("conn2", 101.0, "192.0.2.11", "198.51.100.8"),
            dns("dns1"),
        ];
        store.append_all(&events).unwrap();
        assert_eq!(store.len().unwrap(), 3);

        let rows = store.query_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].uid, "conn1");
        assert_eq!(rows[1].uid, "conn2");
    }

    #[test]
    fn host_filter_matches_src_or_dst() {
        let mut store = MemoryStore::new();
        store
            .append(&conn("conn1", 100.0, "192.0.2.10", "198.51.100.7"))
            .unwrap();

        let by_src = FlowFilter {
            host: Some("192.0.2.10".to_string()),
            ..FlowFilter::default()
        };
        assert_eq!(store.query_flows(&by_src).unwrap().len(), 1);

        let by_dst = FlowFilter {
            host: Some("198.51.100.7".to_string()),
            ..FlowFilter::default()
        };
        assert_eq!(store.query_flows(&by_dst).unwrap().len(), 1);

        let other = FlowFilter {
            host: Some("203.0.113.9".to_string()),
            ..FlowFilter::default()
        };
        assert_eq!(store.query_flows(&other).unwrap().len(), 0);
    }

    #[test]
    fn since_filter_is_inclusive() {
        let mut store = MemoryStore::new();
        store
            .append(&conn("conn1", 100.0, "192.0.2.10", "198.51.100.7"))
            .unwrap();

        let equal = FlowFilter {
            since_ts: Some(100.0),
            ..FlowFilter::default()
        };
        assert_eq!(store.query_flows(&equal).unwrap().len(), 1);

        let above = FlowFilter {
            since_ts: Some(100.5),
            ..FlowFilter::default()
        };
        assert_eq!(store.query_flows(&above).unwrap().len(), 0);
    }

    #[test]
    fn load_file_parses_ndjson() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events-1000-0001.ndjson");
        let mut f = fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"{{"event":"dns","uid":"dns1","ts":200.0,"src":"192.0.2.10","dst":"198.51.100.7","src_port":5353,"dst_port":53,"txid":4660,"is_response":false,"rcode":0,"query":"example.com.","qtype":1,"answers":[]}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"event":"conn","uid":"conn1","ts":100.0,"duration":1.5,"proto":"tcp","conn_state":"SF","end_reason":"fin","src":"192.0.2.10","dst":"198.51.100.7","src_port":1234,"dst_port":80,"pkts_a_to_b":5,"bytes_a_to_b":600,"pkts_b_to_a":4,"bytes_b_to_a":500}}"#
        )
        .unwrap();
        writeln!(f).unwrap(); // blank line skipped
        drop(f);

        let mut store = MemoryStore::new();
        load_file(&mut store, &path).unwrap();
        assert_eq!(store.len().unwrap(), 2);
        assert_eq!(store.query_flows(&FlowFilter::default()).unwrap().len(), 1);
    }

    #[test]
    fn load_file_bad_line_reports_path_and_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("events-1000-0001.ndjson");
        let mut f = fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"{{"event":"dns","uid":"dns1","ts":200.0,"src":"192.0.2.10","dst":"198.51.100.7","src_port":5353,"dst_port":53,"txid":4660,"is_response":false,"rcode":0,"query":"example.com.","qtype":1,"answers":[]}}"#
        )
        .unwrap();
        writeln!(f, "not json").unwrap();
        drop(f);

        let mut store = MemoryStore::new();
        let err = load_file(&mut store, &path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(path.file_name().unwrap().to_str().unwrap()),
            "message lacks file name: {msg}"
        );
        assert!(msg.contains(":2:"), "message lacks line number: {msg}");
        assert!(msg.contains("invalid event"), "message lacks cause: {msg}");
    }

    /// Synthetic alert event with fully explicit fields.
    fn alert(uid: &str, ts: f64, name: &str, severity: Severity) -> Event {
        Event::Alert(AlertEvent {
            uid: uid.to_string(),
            ts,
            name: name.to_string(),
            severity,
            src: "192.0.2.66".to_string(),
            dst: Some("198.51.100.7".to_string()),
            message: "synthetic alert".to_string(),
            evidence: vec![],
        })
    }

    #[test]
    fn query_alerts_filters() {
        let mut store = MemoryStore::new();
        store
            .append_all(&[
                alert("a1", 100.0, "port-scan", Severity::Medium),
                alert("a2", 101.0, "arp-spoof", Severity::High),
                conn("conn1", 102.0, "192.0.2.10", "198.51.100.7"),
            ])
            .unwrap();
        assert_eq!(
            store.query_alerts(&AlertFilter::default()).unwrap().len(),
            2
        );

        let by_name = AlertFilter {
            name: Some("port-scan".to_string()),
            ..AlertFilter::default()
        };
        let got = store.query_alerts(&by_name).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].uid, "a1");

        let min_high = AlertFilter {
            min_severity: Some(Severity::High),
            ..AlertFilter::default()
        };
        let got = store.query_alerts(&min_high).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].uid, "a2");

        let since = AlertFilter {
            since_ts: Some(101.0),
            ..AlertFilter::default()
        };
        let got = store.query_alerts(&since).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].uid, "a2");
    }

    #[test]
    fn load_dir_sorts_and_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("events-1000-0001.ndjson");
        let second = tmp.path().join("events-2000-0002.ndjson");
        let mut f = fs::File::create(&first).unwrap();
        writeln!(
            f,
            r#"{{"event":"conn","uid":"conn1","ts":100.0,"duration":0.0,"proto":"udp","conn_state":"-","end_reason":"idle","src":"192.0.2.10","dst":"198.51.100.7","src_port":5353,"dst_port":53,"pkts_a_to_b":1,"bytes_a_to_b":71,"pkts_b_to_a":0,"bytes_b_to_a":0}}"#
        )
        .unwrap();
        drop(f);
        let mut f = fs::File::create(&second).unwrap();
        writeln!(
            f,
            r#"{{"event":"conn","uid":"conn2","ts":200.0,"duration":0.0,"proto":"udp","conn_state":"-","end_reason":"idle","src":"192.0.2.11","dst":"198.51.100.7","src_port":5354,"dst_port":53,"pkts_a_to_b":2,"bytes_a_to_b":142,"pkts_b_to_a":0,"bytes_b_to_a":0}}"#
        )
        .unwrap();
        drop(f);
        fs::write(tmp.path().join("notes.txt"), "ignore me").unwrap();

        let mut store = MemoryStore::new();
        load_dir(&mut store, tmp.path()).unwrap();
        assert_eq!(store.len().unwrap(), 2);
        let rows = store.query_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows[0].uid, "conn1");
        assert_eq!(rows[1].uid, "conn2");
    }
}
