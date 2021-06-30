use thiserror::Error;

mod parse_dns;

#[derive(Debug)]
pub struct PacketInfo {
    pub fivetuple: FiveTuple,
    pub ip_payload_length: u16,
    pub dns_response: Option<parse_dns::DnsResponse>,
}

#[derive(Debug)]
pub struct FiveTuple {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Error, Debug)]
pub enum PacketParseError {
    #[error("Packet unable to parse, possibly corrupted")]
    BadPacket,
    #[error("ARP has no L3 payload")]
    IsArp,
    #[error("Unhandled transport layer protocol")]
    UnhandledTransport,
}

pub fn parse_ethernet(
    packet: bytes::Bytes,
    logger: &slog::Logger,
) -> Result<PacketInfo, PacketParseError> {
    let ethernet =
        pnet_packet::ethernet::EthernetPacket::new(&packet).ok_or(PacketParseError::BadPacket)?;
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4(ethernet, logger),
        EtherTypes::Ipv6 => parse_ipv6(ethernet, logger),
        EtherTypes::Arp => Err(PacketParseError::IsArp),
        _ => {
            slog::info!(
                logger,
                "Unknown packet: {} > {}; ethertype: {:?} length: {}",
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet_size(),
            );
            Err(PacketParseError::BadPacket)
        }
    }
}

use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

use pnet_packet::Packet;
use pnet_packet::{PacketSize, PrimitiveValues};

fn parse_ipv4(
    ethernet: EthernetPacket,
    logger: &slog::Logger,
) -> Result<PacketInfo, PacketParseError> {
    match Ipv4Packet::new(ethernet.payload()) {
        Some(header) => parse_transport(
            std::net::IpAddr::V4(header.get_source()),
            std::net::IpAddr::V4(header.get_destination()),
            // IPv4 does not directly define the payload length
            header.get_total_length() - ((header.get_header_length() as u16) * 4),
            header.get_next_level_protocol(),
            header.payload(),
            logger,
        ),
        None => {
            slog::info!(logger, "Malformed IPv4 Packet");
            Err(PacketParseError::BadPacket)
        }
    }
}

fn create_unknown_transport_fivetuple(
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    protocol: IpNextHeaderProtocol,
    logger: &slog::Logger,
) -> FiveTuple {
    slog::info!(
        logger,
        "Unknown Transport: {} > {}; protocol: {:?}",
        source,
        destination,
        protocol
    );
    FiveTuple {
        src: source,
        dst: destination,
        src_port: 0,
        dst_port: 0,
        protocol: protocol.to_primitive_values().0,
    }
}

fn parse_ipv6(
    ethernet: EthernetPacket,
    logger: &slog::Logger,
) -> Result<PacketInfo, PacketParseError> {
    match Ipv6Packet::new(ethernet.payload()) {
        Some(header) => parse_transport(
            std::net::IpAddr::V6(header.get_source()),
            std::net::IpAddr::V6(header.get_destination()),
            header.get_payload_length(),
            header.get_next_header(),
            header.payload(),
            logger,
        )
        .or_else(|e| match e {
            PacketParseError::UnhandledTransport => Ok(PacketInfo {
                fivetuple: create_unknown_transport_fivetuple(
                    std::net::IpAddr::V6(header.get_source()),
                    std::net::IpAddr::V6(header.get_destination()),
                    header.get_next_header(),
                    logger,
                ),
                ip_payload_length: header.get_payload_length(),
                dns_response: None,
            }),
            _ => Err(e),
        }),
        None => {
            slog::info!(logger, "Malformed IPv6 Packet");
            Err(PacketParseError::BadPacket)
        }
    }
}

fn parse_transport(
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    ip_payload_length: u16,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    logger: &slog::Logger,
) -> Result<PacketInfo, PacketParseError> {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            parse_transport_udp(source, destination, ip_payload_length, packet, logger)
        }
        IpNextHeaderProtocols::Tcp => {
            parse_transport_tcp(source, destination, ip_payload_length, packet, logger)
        }
        _ => Err(PacketParseError::UnhandledTransport),
    }
}

fn parse_transport_udp(
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    ip_payload_length: u16,
    packet: &[u8],
    logger: &slog::Logger,
) -> Result<PacketInfo, PacketParseError> {
    match UdpPacket::new(packet) {
        Some(udp) => {
            let src_port = udp.get_source();
            let dst_port = udp.get_destination();
            slog::debug!(
                logger,
                "UDP Packet: {}:{} > {}:{}; length: {}",
                source,
                src_port,
                destination,
                dst_port,
                packet.len()
            );

            if (ip_payload_length as usize) != packet.len() {
                return Err(PacketParseError::BadPacket);
            }

            // Attempt to parse DNS if on the known DNS port
            let mut dns_response = None;
            if src_port == 53 {
                match parse_dns::parse_dns_payload(udp.payload(), logger) {
                    Ok(parsed_response) => {
                        dns_response = Some(parsed_response);
                    }
                    Err(_) => {
                        dns_response = None;
                    }
                }
            }

            Ok(PacketInfo {
                fivetuple: FiveTuple {
                    src: source,
                    dst: destination,
                    src_port,
                    dst_port,
                    protocol: IpNextHeaderProtocols::Udp.to_primitive_values().0,
                },
                ip_payload_length: ip_payload_length,
                dns_response: dns_response,
            })
        }
        None => {
            slog::info!(logger, "Malformed UDP Packet");
            Err(PacketParseError::BadPacket)
        }
    }
}

fn parse_transport_tcp(
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    ip_payload_length: u16,
    packet: &[u8],
    logger: &slog::Logger,
) -> Result<PacketInfo, PacketParseError> {
    match TcpPacket::new(packet) {
        Some(tcp) => {
            let src_port = tcp.get_source();
            let dst_port = tcp.get_destination();
            slog::debug!(
                logger,
                "TCP Packet: {}:{} > {}:{}; length: {}",
                source,
                src_port,
                destination,
                dst_port,
                packet.len()
            );

            if (ip_payload_length as usize) != packet.len() {
                return Err(PacketParseError::BadPacket);
            }

            Ok(PacketInfo {
                fivetuple: FiveTuple {
                    src: source,
                    dst: destination,
                    src_port,
                    dst_port,
                    protocol: IpNextHeaderProtocols::Tcp.to_primitive_values().0,
                },
                ip_payload_length: ip_payload_length,
                dns_response: None,
            })
        }
        None => {
            slog::info!(logger, "Malformed TCP Packet");
            Err(PacketParseError::BadPacket)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ethernet;

    const TEST_IPV4_PACKET: &str = "14c03e83666fe4a47133c971080045000235e844400040061e9e0a000080b9c76d99b63001bbaf5d3bd0d3c31b4b801801f6948700000101080a3b098b4aec67f47616030101fc010001f80303a9a47cf7f55f7386da68128b9da84d8565dc071f965ce761d2230796a9bc620a2003a7231a0f6ee16741a9bb46e38bd85dc29ea5c45ab69dfed0f3fa9039f557610024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a0100018b0000000f000d00000a6d617474396a2e6e657400170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d0020866a8ea435a8ea303dddba9875cec5723f88415b1b0ba8129976e1dac7f9a46500170041047355eede7258e545dd2dc5cce6b7b635d3df79f4061ecbbbedff9eb2eaf2927fbdc89914f349c7f27638e29a7984f5075634aab7cb0c08790f861d64ad316e3d002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c000240010015009400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const TEST_IPV6_PACKET: &str = "145bd1af5dc0e4a47133c97186dd60004fe702250640260017020f8097b000000000000000242a044e42040000000000000000000067c5a401bb5c07ea85f13e4b9c801801fbc63e00000101080a8d33f62c849849241603010200010001fc030331638499a07df01440c31689c1aa4701e3478405716c48ce3125e77bc2e406a2208bee720bab28182c6c2f45ce8f39808164ab2f34a5115927587d64dfa1858b2d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a0100018f0000000d000b000008786b63642e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d0020a2880dc8967058e95ab9dd1b084987f6554f3a9cc23c67db918b67f770cdac3c0017004104b02f928f211882dbb0503634a3459b81e9c4c9e094a1e4ad868faf9a505a33d0b60e3933aba6682c6308ee344c805a6e45cd7ca19be97f3efd7204727681c031002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c000240010015009a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const TEST_DNS_PACKET: &str = "e4a47133c971708bcdad14800800452000a64ed500003a115ea908080808c0a801f10035daa80092fba114178180000100040000000004786b636403636f6d00001c0001c00c001c000100000aff00102a044e42000000000000000000000067c00c001c000100000aff00102a044e42020000000000000000000067c00c001c000100000aff00102a044e42040000000000000000000067c00c001c000100000aff00102a044e42060000000000000000000067";

    fn decode_hex(input: &str) -> Result<bytes::Bytes, std::num::ParseIntError> {
        (0..input.len())
            .step_by(2)
            .map(|chunk_i| u8::from_str_radix(&input[chunk_i..chunk_i + 2], 16))
            .collect()
    }

    fn make_logger() -> slog::Logger {
        use slog::*;
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        slog::Logger::root(drain, o!())
    }

    #[test]
    fn test_parse_ipv6() {
        let log = make_logger();
        let packet_bytes = decode_hex(TEST_IPV6_PACKET).unwrap();
        let result = parse_ethernet(packet_bytes, &log).unwrap();
        let expected_src: std::net::IpAddr = "2600:1702:f80:97b0::24".parse().unwrap();
        let expected_dst: std::net::IpAddr = "2a04:4e42:400::67".parse().unwrap();
        assert_eq!(result.fivetuple.dst_port, 443);
        assert_eq!(result.fivetuple.src_port, 50596);
        assert_eq!(result.fivetuple.src, expected_src);
        assert_eq!(result.fivetuple.dst, expected_dst);
    }

    #[test]
    fn test_parse_ipv4() {
        let log = make_logger();
        let packet_bytes = decode_hex(TEST_IPV4_PACKET).unwrap();
        let result = parse_ethernet(packet_bytes, &log).unwrap();
        assert_eq!(result.fivetuple.dst_port, 443);
    }

    #[test]
    fn test_parse_dns_in_ethernet() {
        let log = make_logger();
        let packet_bytes = decode_hex(TEST_DNS_PACKET).unwrap();
        let result = parse_ethernet(packet_bytes, &log).unwrap();
        assert_eq!(
            result.fivetuple.src,
            "8.8.8.8".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            result.fivetuple.dst,
            "192.168.1.241".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(result.ip_payload_length, 146);
        assert!(!result.dns_response.is_none());
        assert!(!result.dns_response.is_none());
        let dns_response = result.dns_response.unwrap();
        let expected_response = super::parse_dns::DnsResponse {
            fqdn: domain::base::name::Dname::from_chars("xkcd.com.".chars()).unwrap(),
            addresses: vec![
                "2a04:4e42::67".parse().unwrap(),
                "2a04:4e42:200::67".parse().unwrap(),
                "2a04:4e42:400::67".parse().unwrap(),
                "2a04:4e42:600::67".parse().unwrap(),
            ],
        };
        assert_eq!(dns_response, expected_response);
    }
}
