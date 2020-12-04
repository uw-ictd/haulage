#[derive(Debug)]
pub struct FiveTuple {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

pub type EthernetPacketKind<'a> = pnet_packet::ethernet::EthernetPacket<'a>;

#[derive(Debug)]
pub enum PacketParseError {
    BadPacket,
    NotImplemented,
    IsArp,
    UnhandledTransport,
}

impl std::error::Error for PacketParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            PacketParseError::BadPacket => None,
            PacketParseError::NotImplemented => None,
            PacketParseError::IsArp => None,
            PacketParseError::UnhandledTransport => None,
        }
    }
}

impl std::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            PacketParseError::BadPacket => write!(f, "That's a bad packet Harry!"),
            PacketParseError::NotImplemented => {
                write!(f, "Parsing for this packet is not implemented")
            }
            PacketParseError::IsArp => write!(f, "ARP has no L3 payload"),
            PacketParseError::UnhandledTransport => write!(f, "Unhandled transport layer protocol"),
        }
    }
}

pub fn parse_ethernet(
    ethernet: EthernetPacket,
    logger: &slog::Logger,
) -> Result<FiveTuple, PacketParseError> {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4(&ethernet, logger),
        EtherTypes::Ipv6 => parse_ipv6(&ethernet, logger),
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
    ethernet: &EthernetPacket,
    logger: &slog::Logger,
) -> Result<FiveTuple, PacketParseError> {
    match Ipv4Packet::new(ethernet.payload()) {
        Some(header) => parse_transport(
            std::net::IpAddr::V4(header.get_source()),
            std::net::IpAddr::V4(header.get_destination()),
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
    ethernet: &EthernetPacket,
    logger: &slog::Logger,
) -> Result<FiveTuple, PacketParseError> {
    match Ipv6Packet::new(ethernet.payload()) {
        Some(header) => parse_transport(
            std::net::IpAddr::V6(header.get_source()),
            std::net::IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            logger,
        )
        .or_else(|e| match e {
            PacketParseError::UnhandledTransport => Ok(create_unknown_transport_fivetuple(
                std::net::IpAddr::V6(header.get_source()),
                std::net::IpAddr::V6(header.get_destination()),
                header.get_next_header(),
                logger,
            )),
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
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    logger: &slog::Logger,
) -> Result<FiveTuple, PacketParseError> {
    match protocol {
        IpNextHeaderProtocols::Udp => parse_transport_udp(source, destination, packet, logger),
        IpNextHeaderProtocols::Tcp => parse_transport_tcp(source, destination, packet, logger),
        _ => Err(PacketParseError::UnhandledTransport),
    }
}

fn parse_transport_udp(
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    packet: &[u8],
    logger: &slog::Logger,
) -> Result<FiveTuple, PacketParseError> {
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
            Ok(FiveTuple {
                src: source,
                dst: destination,
                src_port,
                dst_port,
                protocol: IpNextHeaderProtocols::Udp.to_primitive_values().0,
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
    packet: &[u8],
    logger: &slog::Logger,
) -> Result<FiveTuple, PacketParseError> {
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
            Ok(FiveTuple {
                src: source,
                dst: destination,
                src_port,
                dst_port,
                protocol: IpNextHeaderProtocols::Tcp.to_primitive_values().0,
            })
        }
        None => {
            slog::info!(logger, "Malformed TCP Packet");
            Err(PacketParseError::BadPacket)
        }
    }
}
