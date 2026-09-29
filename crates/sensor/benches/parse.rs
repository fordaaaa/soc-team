//! Pipeline throughput benches: protocol parsing + flow table folding.

use criterion::{Criterion, criterion_group, criterion_main};
use pnet::datalink::MacAddr;
use pnet_packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::udp::MutableUdpPacket;
use sensor::event::EventPipeline;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{Name, RecordType};

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

fn ipv4_with(
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

fn udp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 8 + payload.len()];
    {
        let mut udp = MutableUdpPacket::new(&mut buf).expect("udp buffer too small");
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length((8 + payload.len()) as u16);
        udp.set_payload(payload);
    }
    buf
}

fn tcp_syn(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 20];
    {
        let mut tcp = MutableTcpPacket::new(&mut buf).expect("tcp buffer too small");
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_data_offset(5);
        tcp.set_flags(0x02);
        tcp.set_window(64240);
    }
    buf
}

fn dns_query_payload(name: &str) -> Vec<u8> {
    let name = Name::from_str(name).expect("valid dns name");
    let mut message = Message::new();
    message
        .set_id(0x1234)
        .set_message_type(MessageType::Query)
        .add_query(Query::query(name, RecordType::A));
    message.to_vec().expect("dns message encodes")
}

fn bench_dns_frame(c: &mut Criterion) {
    let frame = eth_frame(
        EtherTypes::Ipv4,
        &ipv4_with(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(198, 51, 100, 7),
            IpNextHeaderProtocols::Udp,
            &udp_segment(40000, 53, &dns_query_payload("example.com.")),
        ),
    );
    let mut pipeline = EventPipeline::new(Duration::from_secs(60), Duration::from_secs(3600));
    c.bench_function("pipeline_dns_frame", |b| {
        b.iter(|| {
            let events = pipeline.observe(UNIX_EPOCH, frame.len() as u64, black_box(&frame));
            black_box(events);
        })
    });
}

fn bench_tcp_syn_frame(c: &mut Criterion) {
    let frame = eth_frame(
        EtherTypes::Ipv4,
        &ipv4_with(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(198, 51, 100, 7),
            IpNextHeaderProtocols::Tcp,
            &tcp_syn(40000, 443),
        ),
    );
    let mut pipeline = EventPipeline::new(Duration::from_secs(60), Duration::from_secs(3600));
    c.bench_function("pipeline_tcp_syn_frame", |b| {
        b.iter(|| {
            let events = pipeline.observe(UNIX_EPOCH, frame.len() as u64, black_box(&frame));
            black_box(events);
        })
    });
}

criterion_group!(benches, bench_dns_frame, bench_tcp_syn_frame);
criterion_main!(benches);
