use std::env;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use pnet::packet::icmp::{IcmpTypes, echo_request::EchoRequestPacket, echo_reply::EchoReplyPacket};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol};
use pnet::packet::ip::IpNextHeaderProtocols;
use std::thread::sleep;

const ICMP_HEADER_LEN: usize = 8;

fn build_icmp_packet(sequence_number: u16) -> [u8; ICMP_HEADER_LEN] {
    let mut buf = [0u8; ICMP_HEADER_LEN];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut buf).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_sequence_number(sequence_number);
    icmp_packet.set_identifier(0);
    icmp_packet.set_checksum(pnet::util::checksum(&icmp_packet.packet(), 1));
    buf
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <host>", args[0]);
        return;
    }

    let target = args[1].parse::<Ipv4Addr>().expect("Invalid IP address");

    // Wrap IpNextHeaderProtocols::Icmp inside TransportProtocol::Ipv4
    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = transport_channel(1024, protocol).expect("Failed to create transport channel");

    let mut sequence_number = 1;

    loop {
        let icmp_packet = build_icmp_packet(sequence_number);

        let now = Instant::now();

        tx.send_to(EchoRequestPacket::new(&icmp_packet).unwrap(), std::net::IpAddr::V4(target))
            .expect("Failed to send packet");

        let mut iter = icmp_packet_iter(&mut rx);

        match iter.next_with_timeout(Duration::from_secs(1)) {
            Ok(Some((packet, addr))) => {
                if let Some(reply) = EchoReplyPacket::new(packet.packet()) {
                    if reply.get_icmp_type() == IcmpTypes::EchoReply {
                        let elapsed = now.elapsed();
                        println!("Reply from {}: seq={} time={}ms", addr, reply.get_sequence_number(), elapsed.as_millis());
                    }
                }
            }
            Ok(None) => {
                println!("Request timed out.");
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }

        sequence_number += 1;
        sleep(Duration::from_secs(1));
    }
}
