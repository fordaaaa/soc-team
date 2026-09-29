//! DuckDB-backed [`EventStore`] behind the default-off `duckdb` feature,
//! which vendors the full C++ engine; events are stored as JSON blobs with
//! `(ts, kind)` extracted for indexed filtering, and matching conn rows are
//! re-deserialized only after the SQL WHERE clause has narrowed them.

use std::path::Path;

use crate::{AlertFilter, EventStore, FlowFilter, FlowRow, StoreError};
use ::duckdb::types::Value;
use ::duckdb::{Connection, params, params_from_iter};
use sensor::event::{AlertEvent, Event, Severity};

/// DuckDB-backed [`EventStore`] storing every event as a JSON blob.
pub struct DuckStore {
    conn: Connection,
}

impl DuckStore {
    /// Open (or create) a database file and ensure the schema exists.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::with_conn(conn)
    }

    /// Open a private in-memory database (used by tests).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::with_conn(conn)
    }

    fn with_conn(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
    ts   REAL NOT NULL,
    kind TEXT NOT NULL,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events (kind, ts);",
        )?;
        Ok(Self { conn })
    }
}

fn event_ts_kind(event: &Event) -> (f64, &'static str) {
    match event {
        Event::Conn(e) => (e.ts, "conn"),
        Event::Dns(e) => (e.ts, "dns"),
        Event::Ssl(e) => (e.ts, "ssl"),
        Event::Http(e) => (e.ts, "http"),
        Event::Arp(e) => (e.ts, "arp"),
        Event::Alert(e) => (e.ts, "alert"),
        Event::Heartbeat(e) => (e.ts, "heartbeat"),
    }
}

impl EventStore for DuckStore {
    fn append(&mut self, event: &Event) -> Result<(), StoreError> {
        let (ts, kind) = event_ts_kind(event);
        let json = serde_json::to_string(event)?;
        self.conn.execute(
            "INSERT INTO events (ts, kind, json) VALUES (?, ?, ?)",
            params![ts, kind, json],
        )?;
        Ok(())
    }

    /// Batched write: all rows land in one transaction, so a partial
    /// batch never persists.
    fn append_all(&mut self, events: &[Event]) -> Result<(), StoreError> {
        if events.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        for event in events {
            let (ts, kind) = event_ts_kind(event);
            let json = serde_json::to_string(event)?;
            tx.execute(
                "INSERT INTO events (ts, kind, json) VALUES (?, ?, ?)",
                params![ts, kind, json],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn query_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowRow>, StoreError> {
        let mut sql = String::from("SELECT json FROM events WHERE kind = 'conn'");
        let mut args: Vec<Value> = Vec::new();
        if let Some(since) = filter.since_ts {
            sql.push_str(" AND ts >= ?");
            args.push(since.into());
        }
        if let Some(host) = &filter.host {
            sql.push_str(
                " AND (json_extract_string(json, '$.src') = ? OR json_extract_string(json, '$.dst') = ?)",
            );
            args.push(Value::Text(host.clone()));
            args.push(Value::Text(host.clone()));
        }
        sql.push_str(" ORDER BY rowid");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<String> = stmt
            .query_map(params_from_iter(args), |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<String>, ::duckdb::Error>>()?;
        let mut out = Vec::new();
        for line in &rows {
            if let Event::Conn(c) = serde_json::from_str::<Event>(line)? {
                out.push(FlowRow::from_conn(&c));
            }
        }
        Ok(out)
    }

    fn query_alerts(&self, filter: &AlertFilter) -> Result<Vec<AlertEvent>, StoreError> {
        let mut sql = String::from("SELECT json FROM events WHERE kind = 'alert'");
        let mut args: Vec<Value> = Vec::new();
        if let Some(since) = filter.since_ts {
            sql.push_str(" AND ts >= ?");
            args.push(since.into());
        }
        if let Some(name) = &filter.name {
            sql.push_str(" AND json_extract_string(json, '$.name') = ?");
            args.push(Value::Text(name.clone()));
        }
        sql.push_str(" ORDER BY rowid");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<String> = stmt
            .query_map(params_from_iter(args), |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<String>, ::duckdb::Error>>()?;
        let mut out = Vec::new();
        for line in &rows {
            if let Event::Alert(a) = serde_json::from_str::<Event>(line)? {
                // Severity ordering is a Rust-side concern: the enum's
                // declaration order does not survive the JSON round trip.
                if filter.min_severity.is_none_or(|min| a.severity >= min) {
                    out.push(a);
                }
            }
        }
        Ok(out)
    }

    fn len(&self) -> Result<usize, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventStore, FlowFilter};
    use sensor::event::{ConnEvent, DnsEvent, Event, HeartbeatEvent};
    use tempfile;

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
    fn duck_roundtrip_and_filters() {
        let mut store = DuckStore::open_in_memory().unwrap();
        store
            .append_all(&[
                conn("conn1", 100.0, "192.0.2.10", "198.51.100.7"),
                conn("conn2", 101.0, "192.0.2.11", "198.51.100.8"),
                dns("dns1"),
            ])
            .unwrap();
        assert_eq!(store.len().unwrap(), 3);

        let rows = store.query_flows(&FlowFilter::default()).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].uid, "conn1");
        assert_eq!(rows[1].uid, "conn2");

        let since = FlowFilter {
            since_ts: Some(101.0),
            ..FlowFilter::default()
        };
        let rows = store.query_flows(&since).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].uid, "conn2");

        let since = FlowFilter {
            since_ts: Some(100.5),
            ..FlowFilter::default()
        };
        let rows = store.query_flows(&since).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].uid, "conn2");

        let host = FlowFilter {
            host: Some("192.0.2.10".to_string()),
            ..FlowFilter::default()
        };
        let rows = store.query_flows(&host).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].uid, "conn1");
    }

    #[test]
    fn duck_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.db");
        {
            let mut store = DuckStore::open(&path).unwrap();
            store
                .append(&conn("conn1", 100.0, "192.0.2.10", "198.51.100.7"))
                .unwrap();
            assert_eq!(store.len().unwrap(), 1);
        }
        let store = DuckStore::open(&path).unwrap();
        assert_eq!(store.len().unwrap(), 1);
        assert_eq!(store.query_flows(&FlowFilter::default()).unwrap().len(), 1);
    }

    #[test]
    fn duck_heartbeat_stored_not_a_flow() {
        let mut store = DuckStore::open_in_memory().unwrap();
        store
            .append(&Event::Heartbeat(HeartbeatEvent {
                ts: 42.0,
                total_frames: 1,
                bytes: 2,
                active_flows: 0,
                events_emitted: 1,
            }))
            .unwrap();
        assert_eq!(store.len().unwrap(), 1);
        assert!(
            store
                .query_flows(&FlowFilter::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn duck_batched_append_all_persists_every_row() {
        let mut store = DuckStore::open_in_memory().unwrap();
        let events: Vec<Event> = (0..50)
            .map(|i| {
                conn(
                    &format!("conn{i}"),
                    100.0 + f64::from(i),
                    "192.0.2.10",
                    "198.51.100.7",
                )
            })
            .collect();
        store.append_all(&events).unwrap();
        assert_eq!(store.len().unwrap(), 50);
        assert_eq!(store.query_flows(&FlowFilter::default()).unwrap().len(), 50);
    }

    /// Synthetic alert event with fully explicit fields.
    fn alert_event(uid: &str, ts: f64, name: &str, severity: Severity) -> Event {
        Event::Alert(AlertEvent {
            uid: uid.to_string(),
            ts,
            name: name.to_string(),
            severity,
            src: "192.0.2.66".to_string(),
            dst: None,
            message: "synthetic alert".to_string(),
            evidence: vec![],
        })
    }

    #[test]
    fn duck_alerts_roundtrip_and_filters() {
        let mut store = DuckStore::open_in_memory().unwrap();
        store
            .append_all(&[
                alert_event("a1", 100.0, "port-scan", Severity::Medium),
                alert_event("a2", 101.0, "arp-spoof", Severity::High),
            ])
            .unwrap();
        assert_eq!(
            store.query_alerts(&AlertFilter::default()).unwrap().len(),
            2
        );

        let by_name = AlertFilter {
            name: Some("arp-spoof".to_string()),
            ..AlertFilter::default()
        };
        let got = store.query_alerts(&by_name).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].severity, Severity::High);

        let min_high = AlertFilter {
            min_severity: Some(Severity::High),
            ..AlertFilter::default()
        };
        let got = store.query_alerts(&min_high).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].uid, "a2");
    }
}
