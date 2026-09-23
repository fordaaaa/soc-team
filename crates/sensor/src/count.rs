//! Pure packet-counting logic — no I/O, unit-testable.
//!
//! Frames are classified by EtherType via `pnet_packet::ethernet`.

use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use std::time::Instant;

/// Aggregate counters over captured frames.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinkStats {
    /// Total frames seen.
    pub total_frames: u64,
    /// Total bytes seen (sum of frame lengths).
    pub bytes: u64,
    /// Frames with EtherType IPv4.
    pub ipv4: u64,
    /// Frames with EtherType IPv6.
    pub ipv6: u64,
    /// Frames with EtherType ARP.
    pub arp: u64,
    /// All other frames (including unparseable/short ones).
    pub other: u64,
}

/// Counts frames and reports packets-per-second since the last tick.
#[derive(Debug)]
pub struct LinkCounter {
    stats: LinkStats,
    last_tick: Instant,
    last_total: u64,
}

impl LinkCounter {
    /// Create an empty counter, starting the pps clock now.
    pub fn new() -> Self {
        Self {
            stats: LinkStats::default(),
            last_tick: Instant::now(),
            last_total: 0,
        }
    }

    /// Classify one raw Ethernet frame and bump the counters.
    pub fn record_frame(&mut self, frame: &[u8]) {
        self.stats.total_frames += 1;
        self.stats.bytes += frame.len() as u64;
        match EthernetPacket::new(frame) {
            Some(pkt) => match pkt.get_ethertype() {
                EtherTypes::Ipv4 => self.stats.ipv4 += 1,
                EtherTypes::Ipv6 => self.stats.ipv6 += 1,
                EtherTypes::Arp => self.stats.arp += 1,
                _ => self.stats.other += 1,
            },
            None => self.stats.other += 1,
        }
    }

    /// Current snapshot of the counters.
    pub fn snapshot(&self) -> LinkStats {
        self.stats
    }

    /// Packets per second since the previous call; resets the tick clock.
    pub fn pps_since(&mut self) -> f64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_tick).as_secs_f64();
        let delta = self.stats.total_frames.saturating_sub(self.last_total);
        self.last_tick = now;
        self.last_total = self.stats.total_frames;
        if elapsed > 0.0 {
            delta as f64 / elapsed
        } else {
            0.0
        }
    }
}

impl Default for LinkCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::MutablePacket;
    use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
    use pnet_packet::udp::MutableUdpPacket;

    fn test_mac() -> pnet::datalink::MacAddr {
        pnet::datalink::MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
    }

    /// Build a minimal Ethernet(IPv4(UDP)) frame.
    fn ipv4_udp_frame() -> Vec<u8> {
        // UDP datagram: 8-byte header + 4-byte payload.
        let mut udp_buf = vec![0u8; 12];
        {
            let mut udp = MutableUdpPacket::new(&mut udp_buf).expect("udp buffer too small");
            udp.set_source(1234);
            udp.set_destination(53);
            udp.set_length(12);
            udp.set_payload(&[1, 2, 3, 4]);
        }
        // IPv4 packet wrapping the UDP datagram.
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
        // Ethernet frame wrapping the IPv4 packet.
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
            // ARP payload: htype=1 (ethernet), ptype=0x0800 (ipv4).
            let payload = eth.packet_mut();
            payload[14] = 0x00;
            payload[15] = 0x01;
            payload[16] = 0x08;
            payload[17] = 0x00;
        }
        eth_buf
    }

    #[test]
    fn classifies_ipv4_and_arp_frames() {
        let mut counter = LinkCounter::new();
        let v4 = ipv4_udp_frame();
        let arp = arp_frame();

        counter.record_frame(&v4);
        counter.record_frame(&arp);

        let snap = counter.snapshot();
        assert_eq!(snap.total_frames, 2);
        assert_eq!(snap.ipv4, 1);
        assert_eq!(snap.arp, 1);
        assert_eq!(snap.ipv6, 0);
        assert_eq!(snap.other, 0);
        assert_eq!(snap.bytes, (v4.len() + arp.len()) as u64);
    }

    #[test]
    fn short_frames_count_as_other() {
        let mut counter = LinkCounter::new();
        counter.record_frame(&[0u8; 5]);
        let snap = counter.snapshot();
        assert_eq!(snap.total_frames, 1);
        assert_eq!(snap.other, 1);
        assert_eq!(snap.bytes, 5);
    }
}
