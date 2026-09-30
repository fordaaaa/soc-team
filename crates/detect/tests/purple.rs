//! Purple-team integration tests: synthetic attack frames go through
//! the real sensor pipeline, and the default detection set must fire.

use detect::{LiveEngine, RuleEngine, SniWatchDetector};
use pnet::datalink::MacAddr;
use pnet_packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::udp::MutableUdpPacket;
use sensor::event::{Event, EventPipeline, Severity, SslEvent};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{Name, RecordType};

const TCP_SYN: u8 = 0x02;

fn ts(secs: u64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn mac(byte: u8) -> MacAddr {
    MacAddr(0x02, 0x00, 0x00, 0x00, 0x00, byte)
}

fn eth_frame(ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 14 + payload.len()];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf).expect("eth buffer too small");
        eth.set_destination(mac(0x01));
        eth.set_source(mac(0x02));
        eth.set_ethertype(ethertype);
        eth.set_payload(payload);
    }
    buf
}

fn tcp_segment(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut buf = vec![0u8; 20];
    {
        let mut tcp = MutableTcpPacket::new(&mut buf).expect("tcp buffer too small");
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(0);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(64240);
    }
    buf
}

fn ipv4_packet_with(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: IpNextHeaderProtocol,
    transport: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 20 + transport.len()];
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).expect("ipv4 buffer too small");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + transport.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(proto);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_payload(transport);
    }
    buf
}

fn syn_frame(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let seg = tcp_segment(src_port, dst_port, TCP_SYN);
    eth_frame(
        EtherTypes::Ipv4,
        &ipv4_packet_with(src, dst, IpNextHeaderProtocols::Tcp, &seg),
    )
}

fn udp_dns_frame(src: Ipv4Addr, dst: Ipv4Addr, query_name: &str) -> Vec<u8> {
    let name = Name::from_str(query_name).expect("valid dns name");
    let mut message = Message::new();
    message
        .set_id(0x1234)
        .set_message_type(MessageType::Query)
        .add_query(Query::query(name, RecordType::A));
    let payload = message.to_vec().expect("dns message encodes");
    let mut buf = vec![0u8; 8 + payload.len()];
    {
        let mut udp = MutableUdpPacket::new(&mut buf).expect("udp buffer too small");
        udp.set_source(40000);
        udp.set_destination(53);
        udp.set_length((8 + payload.len()) as u16);
        udp.set_payload(&payload);
    }
    eth_frame(
        EtherTypes::Ipv4,
        &ipv4_packet_with(src, dst, IpNextHeaderProtocols::Udp, &buf),
    )
}

fn arp_reply_frame(sender_ip: [u8; 4], sender_mac: [u8; 6]) -> Vec<u8> {
    let mut body = Vec::with_capacity(28);
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&0x0800u16.to_be_bytes());
    body.push(6);
    body.push(4);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&sender_mac);
    body.extend_from_slice(&sender_ip);
    body.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    body.extend_from_slice(&[10, 0, 0, 1]);
    eth_frame(EtherTypes::Arp, &body)
}

fn pipeline() -> EventPipeline {
    EventPipeline::new(Duration::from_secs(60), Duration::from_secs(3600))
}

#[test]
fn syn_sweep_fires_port_scan() {
    let mut pipe = pipeline();
    let attacker = Ipv4Addr::new(192, 0, 2, 66);
    let target = Ipv4Addr::new(198, 51, 100, 7);
    for i in 0..15u16 {
        let frame = syn_frame(attacker, target, 40000 + i, 1000 + i);
        let _ = pipe.observe(ts(i as u64), frame.len() as u64, &frame);
    }
    let events = pipe.finish();
    let mut engine = RuleEngine::with_defaults();
    let alerts = engine.run(&events);
    assert!(
        alerts
            .iter()
            .any(|a| a.name == "port-scan" && a.src == "192.0.2.66"),
        "expected a port-scan alert, got: {alerts:?}"
    );
}

#[test]
fn regular_callbacks_fire_beaconing() {
    let mut pipe = pipeline();
    let attacker = Ipv4Addr::new(192, 0, 2, 66);
    let c2 = Ipv4Addr::new(198, 51, 100, 99);
    for i in 0..5u16 {
        // Distinct source ports: five separate flows, one per callback.
        let frame = syn_frame(attacker, c2, 40000 + i, 443);
        let _ = pipe.observe(ts((i * 60) as u64), frame.len() as u64, &frame);
    }
    let events = pipe.finish();
    let mut engine = RuleEngine::with_defaults();
    let alerts = engine.run(&events);
    assert!(
        alerts
            .iter()
            .any(|a| a.name == "beaconing" && a.severity == Severity::High),
        "expected a beaconing alert, got: {alerts:?}"
    );
}

#[test]
fn long_label_query_fires_dns_tunnel() {
    let mut pipe = pipeline();
    let attacker = Ipv4Addr::new(192, 0, 2, 66);
    let resolver = Ipv4Addr::new(198, 51, 100, 7);
    let frame = udp_dns_frame(
        attacker,
        resolver,
        &format!("{}.tunnel.example", "a".repeat(60)),
    );
    let events = pipe.observe(ts(0), frame.len() as u64, &frame);
    assert!(events.iter().any(|event| matches!(event, Event::Dns(_))));
    let mut engine = RuleEngine::with_defaults();
    let alerts = engine.run(&events);
    assert!(
        alerts
            .iter()
            .any(|a| a.name == "dns-tunnel" && a.severity == Severity::High),
        "expected a dns-tunnel alert, got: {alerts:?}"
    );
}

#[test]
fn dueling_macs_fire_arp_spoof() {
    let mut pipe = pipeline();
    let frames = [
        arp_reply_frame([10, 0, 0, 5], [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01]),
        arp_reply_frame([10, 0, 0, 5], [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x02]),
        arp_reply_frame([10, 0, 0, 5], [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01]),
        arp_reply_frame([10, 0, 0, 5], [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x02]),
    ];
    let mut events = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        events.extend(pipe.observe(ts(i as u64), frame.len() as u64, frame));
    }
    let mut engine = RuleEngine::with_defaults();
    let alerts = engine.run(&events);
    assert!(
        alerts
            .iter()
            .any(|a| a.name == "arp-spoof" && a.src == "10.0.0.5"),
        "expected an arp-spoof alert, got: {alerts:?}"
    );
}

#[test]
fn watched_sni_fires_sni_watchlist() {
    // The default watchlist is empty, so the operator registers one.
    let mut engine = RuleEngine::with_defaults();
    engine.register(Box::new(SniWatchDetector::new(vec![
        "evil.example".to_string(),
    ])));
    let events = vec![Event::Ssl(SslEvent {
        uid: "ssl1".to_string(),
        ts: 0.0,
        src: "192.0.2.66".to_string(),
        dst: "198.51.100.9".to_string(),
        src_port: 4444,
        dst_port: 443,
        version: Some("TLSv1.2".to_string()),
        sni: Some("c2.evil.example".to_string()),
        truncated: false,
    })];
    let alerts = engine.run(&events);
    assert!(
        alerts.iter().any(|a| a.name == "sni-watchlist"),
        "expected an sni-watchlist alert, got: {alerts:?}"
    );
}

#[test]
fn live_engine_fires_scan_once_across_ticks() {
    let mut pipe = pipeline();
    let attacker = Ipv4Addr::new(192, 0, 2, 66);
    let target = Ipv4Addr::new(198, 51, 100, 7);
    for i in 0..15u16 {
        let frame = syn_frame(attacker, target, 40000 + i, 1000 + i);
        let _ = pipe.observe(ts(i as u64), frame.len() as u64, &frame);
    }
    let mut live = LiveEngine::new(RuleEngine::with_defaults(), 600.0, 300.0);
    for event in pipe.finish() {
        live.push(&event);
    }
    let first = live.tick(14.0);
    assert!(
        first.iter().any(|a| a.name == "port-scan"),
        "expected a live port-scan alert, got: {first:?}"
    );
    // The same window on the next tick must not re-fire.
    assert!(
        live.tick(15.0).iter().all(|a| a.name != "port-scan"),
        "cooldown failed: port-scan re-fired on the next tick"
    );
}
