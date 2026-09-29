//! DuckDB-backed [`EventStore`] behind the default-off `duckdb` feature,
//! which vendors the full C++ engine; events are stored as JSON blobs with
//! `(ts, kind)` extracted for filtering and conn rows re-deserialized for flows.

use std::path::Path;

use crate::{EventStore, FlowFilter, FlowRow, StoreError};
use ::duckdb::{Connection, params};
use sensor::event::Event;

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
)",
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

    fn query_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowRow>, StoreError> {
        let mut sql = String::from("SELECT json FROM events WHERE kind = 'conn'");
        if filter.since_ts.is_some() {
            sql.push_str(" AND ts >= ?");
        }
        sql.push_str(" ORDER BY rowid");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<String> = match filter.since_ts {
            Some(since) => stmt
                .query_map(params![since], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<String>, ::duckdb::Error>>()?,
            None => stmt
                .query_map(params![], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<String>, ::duckdb::Error>>()?,
        };
        let mut out = Vec::new();
        for line in &rows {
            let event: Event = serde_json::from_str(line)?;
            if let Event::Conn(c) = event
                && filter
                    .host
                    .as_ref()
                    .is_none_or(|host| host == &c.src || host == &c.dst)
            {
                out.push(FlowRow::from_conn(&c));
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
}
