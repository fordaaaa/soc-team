//! socteam console — live stats snapshot served over HTTP/WS.
//!
//! A background reader thread owns the [`PacketSource`], folds frames into
//! a [`LinkCounter`], and publishes a [`Snapshot`] on an interval. Axum
//! serves the snapshot as JSON, over WebSocket, and behind a small page.

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
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

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

/// Serve the bundled console page.
async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("index.html"),
    )
}

/// Serve the latest snapshot, or 503 while the reader is starting.
async fn stats(State(collector): State<Arc<SnapshotCollector>>) -> impl IntoResponse {
    match collector.snapshot() {
        Some(snap) => (StatusCode::OK, Json(snap)).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "starting"})),
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
    State(collector): State<Arc<SnapshotCollector>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, collector))
}

async fn handle_ws(mut ws: WebSocket, collector: Arc<SnapshotCollector>) {
    let mut interval = tokio::time::interval(Duration::from_millis(1000));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let Some(snap) = collector.snapshot() else {
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

/// Build the console router with the shared collector as state.
pub fn router(collector: Arc<SnapshotCollector>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/stats", get(stats))
        .route("/api/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(collector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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
        let app = router(Arc::new(SnapshotCollector::new()));
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
        let app = router(Arc::new(SnapshotCollector::new()));
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
        let app = router(Arc::clone(&collector));
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
        let app = router(Arc::new(SnapshotCollector::new()));
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
}
