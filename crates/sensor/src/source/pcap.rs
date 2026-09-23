//! Offline replay from pcap files via the pure-Rust `pcap-file` crate.

use super::{CapturedPacket, PacketSource, SourceError, SourceItem};
use anyhow::Context;
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Offline source reading frames from a pcap file.
///
/// Yields frames with their pcap timestamps; `None` means clean EOF.
/// Malformed or truncated input surfaces as `Some(Err(_))`, never panics.
pub struct PcapSource {
    reader: PcapReader<BufReader<File>>,
}

impl PcapSource {
    /// Open a pcap file for replay.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("failed to open pcap '{}'", path.display()))?;
        let reader = PcapReader::new(BufReader::new(file))
            .map_err(SourceError::from)
            .with_context(|| format!("invalid pcap header in '{}'", path.display()))?;
        Ok(Self { reader })
    }
}

impl PacketSource for PcapSource {
    type Item = SourceItem;

    fn next_packet(&mut self) -> Option<Self::Item> {
        match self.reader.next_packet() {
            None => None,
            Some(Ok(pkt)) => {
                let timestamp = UNIX_EPOCH.checked_add(pkt.timestamp).unwrap_or(UNIX_EPOCH);
                Some(Ok(CapturedPacket::new(
                    pkt.data.into_owned(),
                    timestamp,
                    pkt.orig_len,
                )))
            }
            Some(Err(e)) => Some(Err(SourceError::from(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_file::pcap::{PcapPacket, PcapWriter};
    use pnet_packet::MutablePacket;
    use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
    use pnet_packet::udp::MutableUdpPacket;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    fn test_mac() -> pnet::datalink::MacAddr {
        pnet::datalink::MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    }

    /// Build a minimal Ethernet(IPv4(UDP)) frame.
    fn ipv4_udp_frame() -> Vec<u8> {
        let mut udp_buf = vec![0u8; 12];
        {
            let mut udp = MutableUdpPacket::new(&mut udp_buf).expect("udp buffer too small");
            udp.set_source(1234);
            udp.set_destination(53);
            udp.set_length(12);
            udp.set_payload(&[1, 2, 3, 4]);
        }
        let mut ip_buf = vec![0u8; 20 + udp_buf.len()];
        {
            let mut ip = MutableIpv4Packet::new(&mut ip_buf).expect("ipv4 buffer too small");
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + udp_buf.len()) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocol::new(IpNextHeaderProtocols::Udp.0));
            ip.set_source(127.into());
            ip.set_destination(127.into());
            ip.set_flags(Ipv4Flags::DontFragment);
            ip.set_payload(&udp_buf);
        }
        let mut eth_buf = vec![0u8; 14 + ip_buf.len()];
        {
            let mut eth =
                MutableEthernetPacket::new(&mut eth_buf).expect("ethernet buffer too small");
            eth.set_destination(test_mac());
            eth.set_source(test_mac());
            eth.set_ethertype(EtherTypes::Ipv4);
            eth.set_payload(&ip_buf);
        }
        eth_buf
    }

    /// Build a minimal Ethernet(ARP) frame (28-byte ARP payload).
    fn arp_frame() -> Vec<u8> {
        let mut eth_buf = vec![0u8; 14 + 28];
        {
            let mut eth =
                MutableEthernetPacket::new(&mut eth_buf).expect("ethernet buffer too small");
            eth.set_destination(test_mac());
            eth.set_source(test_mac());
            eth.set_ethertype(EtherTypes::Arp);
            let payload = eth.packet_mut();
            payload[14] = 0x00;
            payload[15] = 0x01;
            payload[16] = 0x08;
            payload[17] = 0x00;
        }
        eth_buf
    }

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Unique temp path without extra deps (pid + nanos + counter).
    fn unique_temp_pcap(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "socteam-sensor-{name}-{}-{}-{n}.pcap",
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn pcap_round_trip_preserves_frames_and_timestamps() {
        let v4 = ipv4_udp_frame();
        let arp = arp_frame();
        let junk = vec![0xAA, 0xBB, 0xCC];
        let frames = [v4.clone(), arp.clone(), junk.clone()];
        let stamps = [
            Duration::from_secs(0),
            Duration::from_secs(1_709_164_800),
            Duration::from_secs(2_147_483_648),
        ];

        let path = unique_temp_pcap("roundtrip");
        {
            let file = File::create(&path).expect("create temp pcap");
            let mut writer = PcapWriter::new(file).expect("pcap writer header");
            for (frame, ts) in frames.iter().zip(stamps.iter()) {
                let pkt = PcapPacket::new_owned(*ts, frame.len() as u32, frame.clone());
                writer.write_packet(&pkt).expect("write packet");
            }
        }

        let mut src = PcapSource::open(&path).expect("open temp pcap");
        let mut got_frames = Vec::new();
        let mut got_stamps = Vec::new();
        let mut got_orig_lens = Vec::new();
        while let Some(item) = src.next_packet() {
            let pkt = item.expect("packet read must succeed");
            got_frames.push(pkt.data);
            got_stamps.push(pkt.timestamp);
            got_orig_lens.push(pkt.original_len);
        }
        let _ = std::fs::remove_file(&path);

        assert_eq!(got_frames.len(), 3, "packet count");
        assert_eq!(got_frames[0], v4);
        assert_eq!(got_frames[1], arp);
        assert_eq!(got_frames[2], junk);
        for (i, ts) in stamps.iter().enumerate() {
            let expect = UNIX_EPOCH.checked_add(*ts).unwrap();
            assert_eq!(got_stamps[i], expect, "timestamp {i}");
            assert_eq!(got_orig_lens[i], frames[i].len() as u32, "orig_len {i}");
        }
    }

    #[test]
    fn truncated_pcap_errors_instead_of_panicking() {
        let frame = ipv4_udp_frame();
        let full_path = unique_temp_pcap("trunc-full");
        {
            let file = File::create(&full_path).expect("create temp pcap");
            let mut writer = PcapWriter::new(file).expect("pcap writer header");
            let pkt = PcapPacket::new_owned(Duration::from_secs(0), frame.len() as u32, frame);
            writer.write_packet(&pkt).expect("write packet");
        }
        let bytes = std::fs::read(&full_path).expect("read temp pcap");
        let _ = std::fs::remove_file(&full_path);
        // Global header (24) + partial packet header: cut inside the packet
        // record so the next read is truncated.
        assert!(bytes.len() > 30, "fixture too small to truncate");
        let cut = bytes.len().min(30);
        let trunc_path = unique_temp_pcap("trunc-cut");
        std::fs::write(&trunc_path, &bytes[..cut]).expect("write truncated pcap");

        let mut src = PcapSource::open(&trunc_path).expect("header still valid");
        let mut saw_error = false;
        // Bound the loop: a buggy reader must not spin forever.
        for _ in 0..16 {
            match src.next_packet() {
                None => break,
                Some(Ok(_)) => continue,
                Some(Err(_)) => {
                    saw_error = true;
                    break;
                }
            }
        }
        let _ = std::fs::remove_file(&trunc_path);
        assert!(saw_error, "truncated pcap must yield an error, not EOF");
    }
}
