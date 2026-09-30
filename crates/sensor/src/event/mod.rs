//! Zeek-inspired event model (re-exported from the [`events`] crate)
//! plus the sensor-side pipeline and NDJSON sink.

pub mod pipeline;
pub mod sink;

pub use events::{
    AlertEvent, ArpEvent, ConnEvent, DnsEvent, Event, HeartbeatEvent, HttpEvent, HttpKind,
    Severity, SslEvent, proto_name, unix_ts,
};
pub use pipeline::EventPipeline;
pub use sink::{NdjsonSink, RetentionPolicy};
