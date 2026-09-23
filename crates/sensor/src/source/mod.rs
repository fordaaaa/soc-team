//! Packet sources — sync iterators over captured frames.
//!
//! [`PacketSource`] abstracts live capture ([`datalink::DatalinkSource`])
//! and offline replay ([`pcap::PcapSource`]). Each item carries the raw
//! frame bytes, a capture timestamp, and the on-wire length
//! (which may exceed the captured length when snaplen truncates).

pub mod datalink;
pub mod pcap;
pub mod time;

pub use datalink::DatalinkSource;
pub use pcap::PcapSource;
pub use time::{civil_from_unix_secs, now_iso8601};

use std::time::SystemTime;

/// One captured frame with its metadata.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    /// Raw frame bytes (link-layer frame, e.g. Ethernet).
    pub data: Vec<u8>,
    /// Capture timestamp (live: `SystemTime::now()` at receipt;
    /// pcap: file timestamp mapped onto `UNIX_EPOCH`).
    pub timestamp: SystemTime,
    /// Original on-wire length; may exceed `data.len()` under snaplen.
    pub original_len: u32,
}

impl CapturedPacket {
    /// Build a packet from its parts.
    pub fn new(data: Vec<u8>, timestamp: SystemTime, original_len: u32) -> Self {
        Self {
            data,
            timestamp,
            original_len,
        }
    }

    /// Captured length (bytes actually stored in [`Self::data`]).
    pub fn caplen(&self) -> u32 {
        self.data.len() as u32
    }
}

/// Errors a [`PacketSource`] can yield (as `Err` inside `Some`).
///
/// `None` always means clean end-of-stream (offline EOF); malformed or
/// truncated input must surface as `Some(Err(_))`, never panic.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// Live datalink read failure.
    #[error("datalink read error: {0}")]
    Datalink(String),
    /// Offline pcap parse/read failure (incl. truncated files).
    #[error("pcap error: {0}")]
    Pcap(String),
    /// Underlying I/O failure (e.g. opening the pcap path).
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<pcap_file::PcapError> for SourceError {
    fn from(e: pcap_file::PcapError) -> Self {
        Self::Pcap(e.to_string())
    }
}

impl From<std::io::Error> for SourceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Synchronous source of captured packets.
///
/// `Item` carries the frame bytes, capture timestamp, and wire length;
/// in practice both bundled sources use `Result<CapturedPacket,
/// SourceError>` so `None` means clean EOF while `Some(Err(_))`
/// reports malformed/truncated input without panicking.
pub trait PacketSource {
    /// Item yielded per packet (carries bytes + timestamp + wire len).
    type Item;
    /// Return the next packet, or `None` on clean end-of-stream.
    fn next_packet(&mut self) -> Option<Self::Item>;
}

/// Convenience alias used by the bundled sources and the binary.
pub type SourceItem = Result<CapturedPacket, SourceError>;
