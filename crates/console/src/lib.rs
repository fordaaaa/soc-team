//! socteam console — live stats snapshot served over HTTP/WS.
//!
//! A background reader thread owns the [`PacketSource`], folds frames into
//! a [`LinkCounter`], and publishes a [`Snapshot`] on an interval. Axum
//! serves the snapshot as JSON, over WebSocket, and behind a small page.
//! When the operator points the console at the sensor's events directory
//! (and optionally an alerts NDJSON file from `socteam detect`), the page
//! also shows recent flows and detection alerts.

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{StatusCode, header},
    response::{IntoResponse, Json},
    routing::get,
};
use sensor::{
    count::LinkCounter,
    source::{PacketSource, SourceItem, now_iso8601},
};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use store::EventStore;

/// Point-in-time counters served by the HTTP API and WebSocket feed.
#[derive(Clone, Serialize)]
pub struct Snapshot {
    /// Source kind: `"live"`, `"pcap"`, or `"sim"`.
    pub source_kind: String,
    /// Total frames seen.
    pub total_frames: u64,
    /// Total bytes seen.
    pub bytes: u64,
    /// Frames with EtherType IPv4.
    pub ipv4: u64,
    /// Frames with EtherType IPv6.
    pub ipv6: u64,
    /// Frames with EtherType ARP.
    pub arp: u64,
    /// All other frames.
    pub other: u64,
    /// Packets per second over the last interval.
    pub pps: f64,
    /// RFC 3339 timestamp of this snapshot.
    pub updated_at: String,
}

/// Thread-safe holder for the latest [`Snapshot`].
pub struct SnapshotCollector {
    current: RwLock<Option<Snapshot>>,
}

impl SnapshotCollector {
    /// Create an empty collector (no snapshot until the reader publishes).
    pub fn new() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    /// Clone the latest snapshot, if any.
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.current.read().ok().and_then(|guard| guard.clone())
    }

    /// Publish a fresh snapshot (used by the reader thread and tests).
    pub fn set_snapshot(&self, s: Snapshot) {
        if let Ok(mut guard) = self.current.write() {
            *guard = Some(s);
        } else {
            tracing::warn!("snapshot lock poisoned; dropping update");
        }
    }

    /// Spawn the reader thread and return the shared collector.
    ///
    /// The thread runs for the lifetime of the process; shutdown is
    /// process exit (same rationale as the sensor binary: the live
    /// datalink reader may block uninterruptibly, so joining it on
    /// shutdown could hang).
    pub fn spawn(
        source: Box<dyn PacketSource<Item = SourceItem> + Send>,
        source_kind: &'static str,
        interval: Duration,
    ) -> Arc<Self> {
        let collector = Arc::new(Self::new());
        let worker = Arc::clone(&collector);
        std::thread::spawn(move || {
            let mut source = source;
            let mut counter = LinkCounter::new();
            let mut last_emit = Instant::now();
            loop {
                match source.next_packet() {
                    Some(Ok(pkt)) => {
                        counter.record_frame(&pkt.data);
                    }
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "source read error");
                    }
                    None => {
                        let pps = counter.pps_since();
                        let stats = counter.snapshot();
                        worker.set_snapshot(Snapshot {
                            source_kind: source_kind.to_owned(),
                            total_frames: stats.total_frames,
                            bytes: stats.bytes,
                            ipv4: stats.ipv4,
                            ipv6: stats.ipv6,
                            arp: stats.arp,
                            other: stats.other,
                            pps,
                            updated_at: now_iso8601(),
                        });
                        break;
                    }
                }
                if last_emit.elapsed() >= interval {
                    let pps = counter.pps_since();
                    let stats = counter.snapshot();
                    worker.set_snapshot(Snapshot {
                        source_kind: source_kind.to_owned(),
                        total_frames: stats.total_frames,
                        bytes: stats.bytes,
                        ipv4: stats.ipv4,
                        ipv6: stats.ipv6,
                        arp: stats.arp,
                        other: stats.other,
                        pps,
                        updated_at: now_iso8601(),
                    });
                    last_emit = Instant::now();
                }
            }
        });
        collector
    }
}

impl Default for SnapshotCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum flows/alerts served per query (the UI is a "recent activity"
/// view, not a query interface — use `socteam` for that).
const MAX_VIEW_ROWS: usize = 50;
/// Minimum gap between event-directory rescans.
const RELOAD_THROTTLE: Duration = Duration::from_millis(500);

/// Shared console state: the live snapshot plus the optional event
/// views (flows and alerts read back from the sensor's NDJSON output).
pub struct ConsoleState {
    collector: Arc<SnapshotCollector>,
    /// Directory of sensor NDJSON events (flows + alerts views).
    events_dir: Option<PathBuf>,
    /// Alert NDJSON file written by `socteam detect`.
    alerts_file: Option<PathBuf>,
    cache: RwLock<Option<CacheEntry>>,
}

struct CacheEntry {
    at: Instant,
    flows: Vec<store::FlowRow>,
    alerts: Vec<sensor::event::AlertEvent>,
}

impl ConsoleState {
    /// Wrap a snapshot collector with optional event views.
    pub fn new(
        collector: Arc<SnapshotCollector>,
        events_dir: Option<PathBuf>,
        alerts_file: Option<PathBuf>,
    ) -> Self {
        Self {
            collector,
            events_dir,
            alerts_file,
            cache: RwLock::new(None),
        }
    }

    /// The latest live snapshot, if any.
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.collector.snapshot()
    }

    fn load_views(&self) -> Result<(), String> {
        if self.events_dir.is_none() && self.alerts_file.is_none() {
            return Err("no events source: start the console with --events <DIR>".to_string());
        }
        if let Ok(guard) = self.cache.read()
            && let Some(entry) = guard.as_ref()
            && entry.at.elapsed() < RELOAD_THROTTLE
        {
            return Ok(());
        }
        let mut flows = Vec::new();
        let mut alerts = Vec::new();
        if let Some(dir) = &self.events_dir {
            let mut mem = store::MemoryStore::new();
            store::load_dir(&mut mem, dir).map_err(|e| e.to_string())?;
            flows = mem
                .query_flows(&store::FlowFilter::default())
                .map_err(|e| e.to_string())?;
            alerts = mem
                .query_alerts(&store::AlertFilter::default())
                .map_err(|e| e.to_string())?;
        }
        if let Some(file) = &self.alerts_file {
            alerts.extend(load_alert_file(file)?);
        }
        flows.sort_by(|a, b| b.ts.total_cmp(&a.ts));
        alerts.sort_by(|a, b| b.ts.total_cmp(&a.ts));
        flows.truncate(MAX_VIEW_ROWS);
        alerts.truncate(MAX_VIEW_ROWS);
        let entry = CacheEntry {
            at: Instant::now(),
            flows,
            alerts,
        };
        if let Ok(mut guard) = self.cache.write() {
            *guard = Some(entry);
        }
        Ok(())
    }

    /// Recent flows (newest first), or an error string when the events
    /// directory is unreadable.
    pub fn flows(&self) -> Result<Vec<store::FlowRow>, String> {
        self.load_views()?;
        Ok(self
            .cache
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|entry| entry.flows.clone()))
            .unwrap_or_default())
    }

    /// Recent alerts (newest first), from the events dir and/or the
    /// detect output file.
    pub fn alerts(&self) -> Result<Vec<sensor::event::AlertEvent>, String> {
        self.load_views()?;
        Ok(self
            .cache
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|entry| entry.alerts.clone()))
            .unwrap_or_default())
    }
}

/// Read tagged alert events out of one NDJSON file (detect output).
fn load_alert_file(path: &std::path::Path) -> Result<Vec<sensor::event::AlertEvent>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut alerts = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<sensor::event::Event>(line) {
            Ok(sensor::event::Event::Alert(alert)) => alerts.push(alert),
            Ok(_) => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(alerts)
}

/// Serve the bundled console page.
async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("index.html"),
    )
}

/// Serve the latest snapshot, or 503 while the reader is starting.
async fn stats(State(state): State<Arc<ConsoleState>>) -> impl IntoResponse {
    match state.snapshot() {
        Some(snap) => (StatusCode::OK, Json(snap)).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "starting"})),
        )
            .into_response(),
    }
}

/// Serve recent flows from the events directory, or 503 when the
/// console was started without `--events`.
async fn flows(State(state): State<Arc<ConsoleState>>) -> impl IntoResponse {
    match state.flows() {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// Serve recent detection alerts, or 503 when no alert source is set.
async fn alerts(State(state): State<Arc<ConsoleState>>) -> impl IntoResponse {
    match state.alerts() {
        Ok(rows) => (StatusCode::OK, Json(rows)).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// Liveness probe.
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

/// Upgrade to WebSocket and stream snapshots roughly once per second.
async fn ws_handler(
    State(state): State<Arc<ConsoleState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut ws: WebSocket, state: Arc<ConsoleState>) {
    let mut interval = tokio::time::interval(Duration::from_millis(1000));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let Some(snap) = state.snapshot() else {
                    continue;
                };
                match serde_json::to_string(&snap) {
                    Ok(text) => {
                        if ws.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to encode snapshot");
                    }
                }
            }
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}

/// Build the console router with the shared state.
pub fn router(state: Arc<ConsoleState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/stats", get(stats))
        .route("/api/flows", get(flows))
        .route("/api/alerts", get(alerts))
        .route("/api/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, header},
    };
    use http_body_util::BodyExt;
    use std::io::Write as _;
    use tower::ServiceExt;

    fn test_state(
        events: Option<std::path::PathBuf>,
        alerts: Option<std::path::PathBuf>,
    ) -> Arc<ConsoleState> {
        Arc::new(ConsoleState::new(
            Arc::new(SnapshotCollector::new()),
            events,
            alerts,
        ))
    }

    fn sample_snapshot(total_frames: u64) -> Snapshot {
        Snapshot {
            source_kind: "sim".to_owned(),
            total_frames,
            bytes: 100,
            ipv4: total_frames,
            ipv6: 0,
            arp: 0,
            other: 0,
            pps: 1.0,
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = router(test_state(None, None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("ok"), "unexpected body: {text}");
    }

    #[tokio::test]
    async fn stats_returns_503_when_starting() {
        let app = router(test_state(None, None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("starting"), "unexpected body: {text}");
    }

    #[tokio::test]
    async fn stats_returns_snapshot_after_set() {
        let collector = Arc::new(SnapshotCollector::new());
        collector.set_snapshot(sample_snapshot(7));
        let state = Arc::new(ConsoleState::new(collector, None, None));
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["total_frames"], 7);
    }

    #[tokio::test]
    async fn index_returns_html() {
        let app = router(test_state(None, None));
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type header")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            content_type.starts_with("text/html"),
            "unexpected content-type: {content_type}"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty(), "expected non-empty page");
    }

    #[tokio::test]
    async fn flows_returns_503_without_events_source() {
        let app = router(test_state(None, None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/flows")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("no events source"), "unexpected body: {text}");
    }

    #[tokio::test]
    async fn flows_reads_rows_from_events_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = std::fs::File::create(dir.path().join("events-1-0001.ndjson")).unwrap();
        writeln!(
            file,
            r#"{{"event":"conn","uid":"conn1","ts":100.0,"duration":1.5,"proto":"tcp","conn_state":"SF","end_reason":"fin","src":"192.0.2.10","dst":"198.51.100.7","src_port":1234,"dst_port":80,"pkts_a_to_b":5,"bytes_a_to_b":600,"pkts_b_to_a":4,"bytes_b_to_a":500}}"#
        )
        .unwrap();
        drop(file);

        let app = router(test_state(Some(dir.path().to_path_buf()), None));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/flows")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["src"], "192.0.2.10");
    }

    #[tokio::test]
    async fn alerts_read_events_dir_and_detect_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = std::fs::File::create(dir.path().join("events-1-0001.ndjson")).unwrap();
        writeln!(
            file,
            r#"{{"event":"alert","uid":"alert1","ts":200.0,"name":"port-scan","severity":"medium","src":"192.0.2.66","dst":"198.51.100.7","message":"scan seen","evidence":[]}}"#
        )
        .unwrap();
        drop(file);
        // The detect output lives outside the events dir in real setups.
        let alerts_dir = tempfile::tempdir().unwrap();
        let alerts_file = alerts_dir.path().join("alerts.ndjson");
        let mut file = std::fs::File::create(&alerts_file).unwrap();
        writeln!(
            file,
            r#"{{"event":"alert","uid":"alert2","ts":300.0,"name":"arp-spoof","severity":"high","src":"10.0.0.5","dst":null,"message":"ip claimed by 2 macs","evidence":[]}}"#
        )
        .unwrap();
        drop(file);

        let app = router(test_state(
            Some(dir.path().to_path_buf()),
            Some(alerts_file),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/alerts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let alerts = value.as_array().unwrap();
        assert_eq!(alerts.len(), 2);
        // Newest first.
        assert_eq!(alerts[0]["uid"], "alert2");
        assert_eq!(alerts[0]["name"], "arp-spoof");
        assert_eq!(alerts[1]["uid"], "alert1");
    }
}
