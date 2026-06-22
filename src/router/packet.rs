use super::SocksLocalRouter;
use ndisapi::IntermediateBuffer;
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket,
    UdpPacket,
};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProxyDirection {
    ToProxy,
    FromProxy,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum PortRewrite {
    ToProxy(u16),
    FromProxy(u16),
}

#[derive(Clone, Copy, Debug)]
enum PacketKind {
    TcpV4,
    TcpV6,
    UdpV4,
    UdpV6,
}

impl PacketKind {
    fn label(self) -> &'static str {
        match self {
            PacketKind::TcpV4 => "TCP",
            PacketKind::TcpV6 => "TCPv6",
            PacketKind::UdpV4 => "UDP",
            PacketKind::UdpV6 => "UDPv6",
        }
    }

    fn is_v6(self) -> bool {
        matches!(self, PacketKind::TcpV6 | PacketKind::UdpV6)
    }
}

#[derive(Clone, Copy, Debug)]
struct PacketInfo {
    kind: PacketKind,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
}

impl SocksLocalRouter {
    pub(super) async fn process_packet(
        &self,
        packet: &mut IntermediateBuffer,
    ) -> Option<ProxyDirection> {
        let info = parse_packet_info(packet)?;
        let src = SocketAddr::new(info.src_ip, info.src_port);
        let dst = SocketAddr::new(info.dst_ip, info.dst_port);

        let rewrite = match info.kind {
            PacketKind::TcpV4 | PacketKind::TcpV6 => {
                self.process_tcp_payload(
                    info.kind.label(),
                    src,
                    dst,
                    info.src_ip,
                    info.dst_ip,
                    info.src_port,
                    info.dst_port,
                    info.kind.is_v6(),
                    info.syn,
                    info.ack,
                    info.rst,
                    info.fin,
                )
                .await
            }
            PacketKind::UdpV4 | PacketKind::UdpV6 => {
                self.process_udp_payload(
                    info.kind.label(),
                    src,
                    dst,
                    info.src_ip,
                    info.dst_ip,
                    info.src_port,
                    info.dst_port,
                    info.kind.is_v6(),
                )
                .await
            }
        };

        apply_rewrite(packet, &info, rewrite)
    }
}

fn parse_packet_info(packet: &mut IntermediateBuffer) -> Option<PacketInfo> {
    let length = packet.get_length() as usize;
    if length < 14 {
        return None;
    }
    let buffer = packet.get_data_mut();

    let mut frame = match EthernetFrame::<&mut [u8]>::new_checked(&mut buffer[..length]) {
        Ok(frame) => frame,
        Err(_) => return None,
    };

    match frame.ethertype() {
        EthernetProtocol::Ipv4 => parse_ipv4(&mut frame),
        EthernetProtocol::Ipv6 => parse_ipv6(&mut frame),
        _ => None,
    }
}

fn parse_ipv4(frame: &mut EthernetFrame<&mut [u8]>) -> Option<PacketInfo> {
    let mut ipv4 = match Ipv4Packet::new_checked(frame.payload_mut()) {
        Ok(pkt) => pkt,
        Err(_) => return None,
    };

    let src_ip = IpAddr::V4(ipv4.src_addr());
    let dst_ip = IpAddr::V4(ipv4.dst_addr());

    match ipv4.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ipv4.payload_mut()).ok()?;
            Some(PacketInfo {
                kind: PacketKind::TcpV4,
                src_ip,
                dst_ip,
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                syn: tcp.syn(),
                ack: tcp.ack(),
                rst: tcp.rst(),
                fin: tcp.fin(),
            })
        }
        IpProtocol::Udp => {
            let dst = ipv4.dst_addr();
            if dst.is_multicast() || dst.is_broadcast() {
                return None;
            }
            let udp = UdpPacket::new_checked(ipv4.payload_mut()).ok()?;
            Some(PacketInfo {
                kind: PacketKind::UdpV4,
                src_ip,
                dst_ip,
                src_port: udp.src_port(),
                dst_port: udp.dst_port(),
                syn: false,
                ack: false,
                rst: false,
                fin: false,
            })
        }
        _ => None,
    }
}

fn parse_ipv6(frame: &mut EthernetFrame<&mut [u8]>) -> Option<PacketInfo> {
    let mut ipv6 = match Ipv6Packet::new_checked(frame.payload_mut()) {
        Ok(pkt) => pkt,
        Err(_) => return None,
    };

    let src_ip = IpAddr::V6(ipv6.src_addr());
    let dst_ip = IpAddr::V6(ipv6.dst_addr());

    match ipv6.next_header() {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ipv6.payload_mut()).ok()?;
            Some(PacketInfo {
                kind: PacketKind::TcpV6,
                src_ip,
                dst_ip,
                src_port: tcp.src_port(),
                dst_port: tcp.dst_port(),
                syn: tcp.syn(),
                ack: tcp.ack(),
                rst: tcp.rst(),
                fin: tcp.fin(),
            })
        }
        IpProtocol::Udp => {
            if ipv6.dst_addr().is_multicast() {
                return None;
            }
            let udp = UdpPacket::new_checked(ipv6.payload_mut()).ok()?;
            Some(PacketInfo {
                kind: PacketKind::UdpV6,
                src_ip,
                dst_ip,
                src_port: udp.src_port(),
                dst_port: udp.dst_port(),
                syn: false,
                ack: false,
                rst: false,
                fin: false,
            })
        }
        _ => None,
    }
}

fn apply_rewrite(
    packet: &mut IntermediateBuffer,
    info: &PacketInfo,
    rewrite: Option<PortRewrite>,
) -> Option<ProxyDirection> {
    let rewrite = rewrite?;
    let length = packet.get_length() as usize;
    if length < 14 {
        return None;
    }
    let buffer = packet.get_data_mut();

    let mut frame = EthernetFrame::<&mut [u8]>::new_checked(&mut buffer[..length]).ok()?;

    match info.kind {
        PacketKind::TcpV4 => apply_tcp_v4(&mut frame, rewrite),
        PacketKind::TcpV6 => apply_tcp_v6(&mut frame, rewrite),
        PacketKind::UdpV4 => apply_udp_v4(&mut frame, rewrite),
        PacketKind::UdpV6 => apply_udp_v6(&mut frame, rewrite),
    }
}

fn apply_tcp_v4(
    frame: &mut EthernetFrame<&mut [u8]>,
    rewrite: PortRewrite,
) -> Option<ProxyDirection> {
    let mut ipv4 = Ipv4Packet::new_checked(frame.payload_mut()).ok()?;
    let mut tcp = TcpPacket::new_checked(ipv4.payload_mut()).ok()?;

    let direction = match rewrite {
        PortRewrite::ToProxy(port) => {
            tcp.set_dst_port(port);
            ProxyDirection::ToProxy
        }
        PortRewrite::FromProxy(port) => {
            tcp.set_src_port(port);
            ProxyDirection::FromProxy
        }
    };

    swap_ipv4(&mut ipv4);
    let src = ipv4.src_addr();
    let dst = ipv4.dst_addr();
    if let Ok(mut tcp) = TcpPacket::new_checked(ipv4.payload_mut()) {
        tcp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
    }
    ipv4.fill_checksum();
    swap_mac(frame);
    Some(direction)
}

fn apply_tcp_v6(
    frame: &mut EthernetFrame<&mut [u8]>,
    rewrite: PortRewrite,
) -> Option<ProxyDirection> {
    let mut ipv6 = Ipv6Packet::new_checked(frame.payload_mut()).ok()?;
    let mut tcp = TcpPacket::new_checked(ipv6.payload_mut()).ok()?;

    let direction = match rewrite {
        PortRewrite::ToProxy(port) => {
            tcp.set_dst_port(port);
            ProxyDirection::ToProxy
        }
        PortRewrite::FromProxy(port) => {
            tcp.set_src_port(port);
            ProxyDirection::FromProxy
        }
    };

    swap_ipv6(&mut ipv6);
    let src = ipv6.src_addr();
    let dst = ipv6.dst_addr();
    if let Ok(mut tcp) = TcpPacket::new_checked(ipv6.payload_mut()) {
        tcp.fill_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst));
    }
    swap_mac(frame);
    Some(direction)
}

fn apply_udp_v4(
    frame: &mut EthernetFrame<&mut [u8]>,
    rewrite: PortRewrite,
) -> Option<ProxyDirection> {
    let mut ipv4 = Ipv4Packet::new_checked(frame.payload_mut()).ok()?;
    let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).ok()?;

    let direction = match rewrite {
        PortRewrite::ToProxy(port) => {
            udp.set_dst_port(port);
            ProxyDirection::ToProxy
        }
        PortRewrite::FromProxy(port) => {
            udp.set_src_port(port);
            ProxyDirection::FromProxy
        }
    };

    swap_ipv4(&mut ipv4);
    let src = ipv4.src_addr();
    let dst = ipv4.dst_addr();
    if let Ok(mut udp) = UdpPacket::new_checked(ipv4.payload_mut()) {
        udp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
    }
    ipv4.fill_checksum();
    swap_mac(frame);
    Some(direction)
}

fn apply_udp_v6(
    frame: &mut EthernetFrame<&mut [u8]>,
    rewrite: PortRewrite,
) -> Option<ProxyDirection> {
    let mut ipv6 = Ipv6Packet::new_checked(frame.payload_mut()).ok()?;
    let mut udp = UdpPacket::new_checked(ipv6.payload_mut()).ok()?;

    let direction = match rewrite {
        PortRewrite::ToProxy(port) => {
            udp.set_dst_port(port);
            ProxyDirection::ToProxy
        }
        PortRewrite::FromProxy(port) => {
            udp.set_src_port(port);
            ProxyDirection::FromProxy
        }
    };

    swap_ipv6(&mut ipv6);
    let src = ipv6.src_addr();
    let dst = ipv6.dst_addr();
    if let Ok(mut udp) = UdpPacket::new_checked(ipv6.payload_mut()) {
        udp.fill_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst));
    }
    swap_mac(frame);
    Some(direction)
}

fn swap_ipv4(ipv4: &mut Ipv4Packet<&mut [u8]>) {
    let src = ipv4.src_addr();
    let dst = ipv4.dst_addr();
    ipv4.set_src_addr(dst);
    ipv4.set_dst_addr(src);
}

fn swap_ipv6(ipv6: &mut Ipv6Packet<&mut [u8]>) {
    let src = ipv6.src_addr();
    let dst = ipv6.dst_addr();
    ipv6.set_src_addr(dst);
    ipv6.set_dst_addr(src);
}

fn swap_mac(frame: &mut EthernetFrame<&mut [u8]>) {
    let src = frame.src_addr();
    let dst = frame.dst_addr();
    frame.set_src_addr(dst);
    frame.set_dst_addr(src);
}
