//! Bidirectional flow tracking over [`crate::proto::FrameInfo`].
//!
//! Frames are folded into flow records keyed by direction-normalized
//! 5-tuple identity. Time is injected by the caller (`SystemTime`
//! parameters) — this module performs no I/O, spawns no threads, and reads
//! no clock.

pub mod key;
pub mod table;

pub use key::FlowKey;
pub use table::{EndReason, FlowRecord, FlowTable};
