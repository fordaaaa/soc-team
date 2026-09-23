//! Deterministic synthetic packet source for demos and tests.
//!
//! [`SimSource`] generates Ethernet frames from a seeded LCG so runs are
//! reproducible without root, hardware, or fixture files. It produces no
//! real traffic: every byte is synthesized locally and paced in-process.

use super::{CapturedPacket, PacketSource, SourceItem};
use pnet::datalink::MacAddr;
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet_packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::udp::MutableUdpPacket;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

/// LCG multiplier from Knuth MMIX (`6364136223846793005`).
const LCG_MULT: u64 = 6364136223846793005;
/// LCG increment from Knuth MMIX (`1442695040888963407`).
const LCG_ADD: u64 = 1442695040888963407;

/// Deterministic synthetic [`PacketSource`] for demos and tests.
///
/// Generates plausible Ethernet frames (mostly IPv4/UDP, some IPv6, ARP,
/// and LLDP-like) from a seeded LCG. It never touches the network, so no
/// real traffic is ever produced or observed; use it wherever a live-like
/// stream is needed without root or hardware.
///
/// The stream is live-like: [`PacketSource::next_packet`] never returns
/// `None`.
pub struct SimSource {
    /// LCG state; advanced once per draw, high bits are consumed.
    state: u64,
    /// Target packets per second; `0` disables pacing (no sleeping).
    pps: u32,
}

impl SimSource {
    /// Create a source deterministically seeded by `seed`.
    ///
    /// `pps` is the target packets-per-second rate; each `next_packet`
    /// call sleeps `1/pps` (jittered ±20%) before yielding. `pps == 0`
    /// disables pacing entirely (tests should use `0`).
    pub fn new(seed: u64, pps: u32) -> Self {
        Self { state: seed, pps }
    }

    /// Advance the LCG and return the new state.
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(LCG_MULT).wrapping_add(LCG_ADD);
        self.state
    }

    /// Next pseudo-random `u32`, taken from the high bits of the LCG.
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Next pseudo-random value in `0..bound`.
    ///
    /// Callers always pass `bound > 0`.
    fn next_range(&mut self, bound: u32) -> u32 {
        debug_assert!(bound > 0, "next_range requires a non-zero bound");
        if bound == 0 {
            return 0;
        }
        self.next_u32() % bound
    }

    /// Fill `buf` with pseudo-random bytes.
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut word = 0u32;
        let mut used = u32::BITS;
        for byte in buf.iter_mut() {
            if used == u32::BITS {
                word = self.next_u32();
                used = 0;
            }
            *byte = (word >> used) as u8;
            used += u8::BITS;
        }
    }

    /// Random unicast, locally-administered MAC (`first byte & 0xFE | 0x02`).
    fn random_mac(&mut self) -> MacAddr {
        let mut octets = [0u8; 6];
        self.fill_bytes(&mut octets);
        octets[0] = (octets[0] & 0xFE) | 0x02;
        MacAddr::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        )
    }

    /// Random IPv4 address.
    fn random_ip(&mut self) -> Ipv4Addr {
        Ipv4Addr::from(self.next_u32())
    }

    /// Random IPv6 address.
    fn random_ip6(&mut self) -> Ipv6Addr {
        let hi = u128::from(self.next_u64());
        let lo = u128::from(self.next_u64());
        Ipv6Addr::from((hi << 64) | lo)
    }

    /// Wrap `inner` (complete L3+ payload) in an Ethernet header.
    fn ethernet_frame(&mut self, ethertype: EtherType, inner: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + inner.len()];
        if let Some(mut eth) = MutableEthernetPacket::new(&mut frame) {
            eth.set_destination(self.random_mac());
            eth.set_source(self.random_mac());
            eth.set_ethertype(ethertype);
            eth.set_payload(inner);
        }
        frame
    }

    /// Build an Ethernet(IPv4(UDP)) frame with a 20–80 byte UDP payload.
    fn build_ipv4(&mut self) -> Vec<u8> {
        let payload_len = 20 + self.next_range(61);
        let mut payload = vec![0u8; payload_len as usize];
        self.fill_bytes(&mut payload);

        let mut udp_buf = vec![0u8; 8 + payload.len()];
        let udp_len = udp_buf.len() as u16;
        if let Some(mut udp) = MutableUdpPacket::new(&mut udp_buf) {
            udp.set_source(self.next_range(65_535) as u16 + 1);
            udp.set_destination(self.next_range(65_535) as u16 + 1);
            udp.set_length(udp_len);
            udp.set_payload(&payload);
        }

        let mut ip_buf = vec![0u8; 20 + udp_buf.len()];
        let ip_len = ip_buf.len() as u16;
        if let Some(mut ip) = MutableIpv4Packet::new(&mut ip_buf) {
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(ip_len);
            ip.set_identification(self.next_u32() as u16);
            ip.set_flags(Ipv4Flags::DontFragment);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(self.random_ip());
            ip.set_destination(self.random_ip());
            ip.set_payload(&udp_buf);
        }

        self.ethernet_frame(EtherTypes::Ipv4, &ip_buf)
    }

    /// Build an Ethernet(IPv6) frame with a minimal header + 20–80 bytes.
    fn build_ipv6(&mut self) -> Vec<u8> {
        let payload_len = 20 + self.next_range(61);
        let mut payload = vec![0u8; payload_len as usize];
        self.fill_bytes(&mut payload);

        let mut ip_buf = vec![0u8; 40 + payload.len()];
        if let Some(mut ip) = MutableIpv6Packet::new(&mut ip_buf) {
            ip.set_version(6);
            ip.set_traffic_class(self.next_u32() as u8);
            ip.set_flow_label(self.next_u32() & 0x000F_FFFF);
            ip.set_payload_length(payload.len() as u16);
            ip.set_next_header(IpNextHeaderProtocols::Udp);
            ip.set_hop_limit(64);
            ip.set_source(self.random_ip6());
            ip.set_destination(self.random_ip6());
            ip.set_payload(&payload);
        }

        self.ethernet_frame(EtherTypes::Ipv6, &ip_buf)
    }

    /// Build an Ethernet(ARP) frame with a 28-byte ARP payload.
    fn build_arp(&mut self) -> Vec<u8> {
        let sender_mac = self.random_mac();
        let sender_ip = self.random_ip();
        let target_mac = self.random_mac();
        let target_ip = self.random_ip();
        let operation = if self.next_range(2) == 0 {
            ArpOperations::Request
        } else {
            ArpOperations::Reply
        };

        let mut arp_buf = vec![0u8; 28];
        if let Some(mut arp) = MutableArpPacket::new(&mut arp_buf) {
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(operation);
            arp.set_sender_hw_addr(sender_mac);
            arp.set_sender_proto_addr(sender_ip);
            arp.set_target_hw_addr(target_mac);
            arp.set_target_proto_addr(target_ip);
        }

        self.ethernet_frame(EtherTypes::Arp, &arp_buf)
    }

    /// Build an LLDP-like frame (ethertype `0x88CC`) with a few bytes.
    fn build_other(&mut self) -> Vec<u8> {
        let payload_len = 8 + self.next_range(13);
        let mut payload = vec![0u8; payload_len as usize];
        self.fill_bytes(&mut payload);
        self.ethernet_frame(EtherType::new(0x88CC), &payload)
    }

    /// Next frame: ~85% IPv4, ~8% IPv6, ~5% ARP, ~2% other; padded so the
    /// total length lands in 60–400 bytes.
    fn next_frame(&mut self) -> Vec<u8> {
        let roll = self.next_range(100);
        let frame = if roll < 85 {
            self.build_ipv4()
        } else if roll < 93 {
            self.build_ipv6()
        } else if roll < 98 {
            self.build_arp()
        } else {
            self.build_other()
        };
        // Ethernet minimum is 60 bytes; stretch small frames with zero pad
        // so every frame lands in 60–400 bytes total.
        let target = 60 + self.next_range(341) as usize;
        if frame.len() >= target {
            frame
        } else {
            let mut padded = frame;
            padded.resize(target, 0);
            padded
        }
    }

    /// Sleep `1/pps` seconds, jittered ±20% from the LCG. No-op when
    /// pacing is disabled (`pps == 0`).
    fn pace(&mut self) {
        if self.pps == 0 {
            return;
        }
        let jitter_percent = 80 + u64::from(self.next_range(41));
        let nanos = 1_000_000_000u64
            .saturating_mul(jitter_percent)
            .saturating_div(u64::from(self.pps).saturating_mul(100));
        std::thread::sleep(Duration::from_nanos(nanos));
    }
}

impl PacketSource for SimSource {
    type Item = SourceItem;

    /// Yield the next synthetic packet; never returns `None` (live-like).
    fn next_packet(&mut self) -> Option<Self::Item> {
        self.pace();
        let frame = self.next_frame();
        let len = frame.len() as u32;
        Some(Ok(CapturedPacket::new(frame, SystemTime::now(), len)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ethernet::EthernetPacket;

    /// Collect the frame bytes of the next `n` packets.
    fn next_frames(source: &mut SimSource, n: usize) -> Vec<Vec<u8>> {
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n {
            let item = source
                .next_packet()
                .expect("sim source never returns None")
                .expect("sim source never fails");
            frames.push(item.data);
        }
        frames
    }

    #[test]
    fn determinism_same_seed_same_stream() {
        let mut first = SimSource::new(42, 0);
        let mut second = SimSource::new(42, 0);
        assert_eq!(next_frames(&mut first, 50), next_frames(&mut second, 50));
    }

    #[test]
    fn distribution_covers_ipv4_ipv6_arp() {
        let mut source = SimSource::new(7, 0);
        let frames = next_frames(&mut source, 5_000);
        let mut ipv4 = 0u32;
        let mut ipv6 = 0u32;
        let mut arp = 0u32;
        for frame in &frames {
            let ethertype = EthernetPacket::new(frame)
                .expect("sim frames are valid Ethernet")
                .get_ethertype();
            if ethertype == EtherTypes::Ipv4 {
                ipv4 += 1;
            } else if ethertype == EtherTypes::Ipv6 {
                ipv6 += 1;
            } else if ethertype == EtherTypes::Arp {
                arp += 1;
            }
        }
        assert!(ipv4 > 0, "expected some IPv4 frames");
        assert!(ipv6 > 0, "expected some IPv6 frames");
        assert!(arp > 0, "expected some ARP frames");
        let fraction = f64::from(ipv4) / frames.len() as f64;
        assert!(
            (0.75..=0.95).contains(&fraction),
            "ipv4 fraction {fraction} outside 0.75..=0.95"
        );
    }

    #[test]
    fn unpaced_stream_is_fast_and_never_none() {
        let mut source = SimSource::new(99, 0);
        let start = SystemTime::now();
        let mut count = 0u32;
        for _ in 0..1_000 {
            let item = source.next_packet();
            assert!(item.is_some(), "sim source never returns None");
            let _ = item.expect("sim source never returns None");
            count += 1;
        }
        assert_eq!(count, 1_000);
        let elapsed = start.elapsed().expect("clock moves forward");
        assert!(
            elapsed < Duration::from_millis(500),
            "1_000 unpaced frames took {elapsed:?}, expected well under a second"
        );
    }

    #[test]
    fn wire_len_matches_frame_len() {
        let mut source = SimSource::new(1234, 0);
        for _ in 0..200 {
            let packet = source
                .next_packet()
                .expect("sim source never returns None")
                .expect("sim source never fails");
            assert_eq!(packet.original_len, packet.data.len() as u32);
            assert!(
                (60..=400).contains(&packet.data.len()),
                "frame len {} outside 60..=400",
                packet.data.len()
            );
        }
    }
}
