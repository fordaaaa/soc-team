//! Live capture via `pnet::datalink`.

use super::{CapturedPacket, PacketSource, SourceError, SourceItem};
use anyhow::Context;
use pnet::datalink::{Channel, Config, DataLinkReceiver};
use std::time::SystemTime;

/// Live Ethernet source backed by a `pnet::datalink` channel receiver.
///
/// Never returns `None` (live capture has no EOF); read failures surface
/// as `Some(Err(_))` so the reader thread can log and continue.
pub struct DatalinkSource {
    rx: Box<dyn DataLinkReceiver>,
}

impl DatalinkSource {
    /// Open `name` for live capture; `promiscuous` is passed through to
    /// the datalink config.
    pub fn open(name: &str, promiscuous: bool) -> anyhow::Result<Self> {
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|i| i.name == name)
            .with_context(|| format!("interface '{name}' not found"))?;
        let config = Config {
            promiscuous,
            ..Config::default()
        };
        let rx = match pnet::datalink::channel(&interface, config)
            .context("failed to open datalink channel (try running with sudo)")?
        {
            Channel::Ethernet(_, rx) => rx,
            _ => anyhow::bail!("unsupported channel type for interface '{name}'"),
        };
        Ok(Self { rx })
    }

    /// Wrap an already-opened receiver (primarily for tests).
    pub fn from_receiver(rx: Box<dyn DataLinkReceiver>) -> Self {
        Self { rx }
    }
}

impl PacketSource for DatalinkSource {
    type Item = SourceItem;

    fn next_packet(&mut self) -> Option<Self::Item> {
        match self.rx.next() {
            Ok(frame) => {
                let len = frame.len() as u32;
                Some(Ok(CapturedPacket::new(
                    frame.to_vec(),
                    SystemTime::now(),
                    len,
                )))
            }
            Err(e) => Some(Err(SourceError::Datalink(e.to_string()))),
        }
    }
}
