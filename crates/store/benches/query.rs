//! Store benches: NDJSON load and query over a 10k-event corpus.

use criterion::{Criterion, criterion_group, criterion_main};
use sensor::event::{ConnEvent, Event};
use std::hint::black_box;
use std::io::Write;
use store::EventStore;

/// Build `count` conn events across many hosts and ports.
fn corpus(count: usize) -> Vec<Event> {
    (0..count)
        .map(|i| {
            Event::Conn(ConnEvent {
                uid: format!("conn{i}"),
                ts: 1_770_000_000.0 + (i % 600) as f64,
                duration: 1.5,
                proto: "tcp".to_string(),
                conn_state: "SF".to_string(),
                end_reason: "fin".to_string(),
                src: format!("192.0.2.{}", i % 200 + 1),
                dst: format!("198.51.100.{}", i % 100 + 1),
                src_port: Some(40000 + (i % 5000) as u16),
                dst_port: Some((i % 300) as u16),
                pkts_a_to_b: 5,
                bytes_a_to_b: 600,
                pkts_b_to_a: 4,
                bytes_b_to_a: 500,
            })
        })
        .collect()
}

fn bench_append_all(c: &mut Criterion) {
    let events = corpus(10_000);
    c.bench_function("store_append_all_10k", |b| {
        b.iter(|| {
            let mut store = store::MemoryStore::new();
            store.append_all(black_box(&events)).unwrap();
            black_box(store.len().unwrap());
        })
    });
}

fn bench_load_dir_ndjson(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let mut file = std::fs::File::create(dir.path().join("events-1-0001.ndjson")).unwrap();
    for event in corpus(10_000) {
        writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
    }
    drop(file);
    c.bench_function("store_load_dir_10k", |b| {
        b.iter(|| {
            let mut store = store::MemoryStore::new();
            store::load_dir(&mut store, black_box(dir.path())).unwrap();
            black_box(store.len().unwrap());
        })
    });
}

fn bench_query_flows_filtered(c: &mut Criterion) {
    let events = corpus(10_000);
    let mut store = store::MemoryStore::new();
    store.append_all(&events).unwrap();
    let filter = store::FlowFilter {
        since_ts: Some(1_770_000_000.0 + 300.0),
        host: Some("192.0.2.1".to_string()),
    };
    c.bench_function("store_query_flows_10k", |b| {
        b.iter(|| {
            let rows = store.query_flows(black_box(&filter)).unwrap();
            black_box(rows.len());
        })
    });
}

criterion_group!(
    benches,
    bench_append_all,
    bench_load_dir_ndjson,
    bench_query_flows_filtered
);
criterion_main!(benches);
