//! socteam sensor crate — Phase 0 skeleton.
//!
//! Counts link-layer frames per EtherType class. I/O lives in the binary;
//! [`count`] is pure logic and unit-tested.
//!
//! Phase 1 replaces the datalink backend on Linux with AF_PACKET rings +
//! eBPF filtering for zero-copy/low latency.

pub mod config;
pub mod count;
pub mod event;
pub mod flow;
pub mod iface;
pub mod notify;
pub mod proto;
pub mod source;
