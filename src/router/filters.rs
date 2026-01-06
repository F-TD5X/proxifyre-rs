use ndisapi::{
    DataLinkLayerFilter, DirectionFlags, FILTER_PACKET_PASS, FilterLayerFlags, IP_SUBNET_V4_TYPE,
    IP_SUBNET_V6_TYPE, IPV4, IPV6, IpAddressV4, IpAddressV4Union, IpAddressV6, IpAddressV6Union,
    IpSubnetV4, IpSubnetV6, IpV4Filter, IpV4FilterFlags, IpV6Filter, IpV6FilterFlags,
    NetworkLayerFilter, NetworkLayerFilterUnion, PortRange, StaticFilter, TCPUDP, TcpUdpFilter,
    TcpUdpFilterFlags, TransportLayerFilter, TransportLayerFilterUnion,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

pub(super) fn build_icmp_pass_filter() -> StaticFilter {
    StaticFilter::new(
        0,
        DirectionFlags::PACKET_FLAG_ON_RECEIVE | DirectionFlags::PACKET_FLAG_ON_SEND,
        FILTER_PACKET_PASS,
        FilterLayerFlags::NETWORK_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(
            IPV4,
            NetworkLayerFilterUnion {
                ipv4: IpV4Filter::new(
                    IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                    IpAddressV4::default(),
                    IpAddressV4::default(),
                    IPPROTO_ICMP,
                ),
            },
        ),
        TransportLayerFilter::default(),
    )
}

pub(super) fn build_proxy_pass_filters(ip: Ipv4Addr, port: u16) -> Vec<StaticFilter> {
    let dest = ipv4_subnet_filter(ip, Ipv4Addr::new(255, 255, 255, 255));
    build_proxy_pass_filters_common(dest, port, build_proxy_pass_filter)
}

pub(super) fn build_proxy_pass_filters_v6(ip: Ipv6Addr, port: u16) -> Vec<StaticFilter> {
    let dest = ipv6_subnet_filter(ip, Ipv6Addr::from(u128::MAX));
    build_proxy_pass_filters_common(dest, port, build_proxy_pass_filter_v6)
}

fn build_proxy_pass_filters_common<T: Copy>(
    dest: T,
    port: u16,
    build: impl Fn(DirectionFlags, T, u8, bool, u16) -> StaticFilter,
) -> Vec<StaticFilter> {
    let tcp_out = build(
        DirectionFlags::PACKET_FLAG_ON_SEND,
        dest,
        IPPROTO_TCP,
        false,
        port,
    );
    let tcp_in = build(
        DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        dest,
        IPPROTO_TCP,
        true,
        port,
    );
    let udp_out = build(
        DirectionFlags::PACKET_FLAG_ON_SEND,
        dest,
        IPPROTO_UDP,
        false,
        port,
    );
    let udp_in = build(
        DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        dest,
        IPPROTO_UDP,
        true,
        port,
    );

    vec![tcp_out, tcp_in, udp_out, udp_in]
}

fn build_proxy_pass_filter(
    direction: DirectionFlags,
    dest: IpAddressV4,
    protocol: u8,
    match_src_port: bool,
    port: u16,
) -> StaticFilter {
    let ip_filter = IpV4Filter::new(
        IpV4FilterFlags::IP_V4_FILTER_PROTOCOL | IpV4FilterFlags::IP_V4_FILTER_DEST_ADDRESS,
        IpAddressV4::default(),
        dest,
        protocol,
    );

    let port_range = PortRange::new(port, port);
    let (src_range, dst_range, port_flag) = if match_src_port {
        (
            port_range,
            PortRange::default(),
            TcpUdpFilterFlags::TCPUDP_SRC_PORT,
        )
    } else {
        (
            PortRange::default(),
            port_range,
            TcpUdpFilterFlags::TCPUDP_DEST_PORT,
        )
    };

    StaticFilter::new(
        0,
        direction,
        FILTER_PACKET_PASS,
        FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(IPV4, NetworkLayerFilterUnion { ipv4: ip_filter }),
        TransportLayerFilter::new(
            TCPUDP,
            TransportLayerFilterUnion {
                tcp_udp: TcpUdpFilter::new(port_flag, src_range, dst_range, 0u8),
            },
        ),
    )
}

fn build_proxy_pass_filter_v6(
    direction: DirectionFlags,
    dest: IpAddressV6,
    protocol: u8,
    match_src_port: bool,
    port: u16,
) -> StaticFilter {
    let ip_filter = IpV6Filter::new(
        IpV6FilterFlags::IP_V6_FILTER_PROTOCOL | IpV6FilterFlags::IP_V6_FILTER_DEST_ADDRESS,
        IpAddressV6::default(),
        dest,
        protocol,
    );

    let port_range = PortRange::new(port, port);
    let (src_range, dst_range, port_flag) = if match_src_port {
        (
            port_range,
            PortRange::default(),
            TcpUdpFilterFlags::TCPUDP_SRC_PORT,
        )
    } else {
        (
            PortRange::default(),
            port_range,
            TcpUdpFilterFlags::TCPUDP_DEST_PORT,
        )
    };

    StaticFilter::new(
        0,
        direction,
        FILTER_PACKET_PASS,
        FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(IPV6, NetworkLayerFilterUnion { ipv6: ip_filter }),
        TransportLayerFilter::new(
            TCPUDP,
            TransportLayerFilterUnion {
                tcp_udp: TcpUdpFilter::new(port_flag, src_range, dst_range, 0u8),
            },
        ),
    )
}

fn ipv4_subnet_filter(ip: Ipv4Addr, mask: Ipv4Addr) -> IpAddressV4 {
    IpAddressV4::new(
        IP_SUBNET_V4_TYPE,
        IpAddressV4Union {
            ip_subnet: IpSubnetV4::new(ipv4_to_in_addr(ip), ipv4_to_in_addr(mask)),
        },
    )
}

fn ipv6_subnet_filter(ip: Ipv6Addr, mask: Ipv6Addr) -> IpAddressV6 {
    IpAddressV6::new(
        IP_SUBNET_V6_TYPE,
        IpAddressV6Union {
            ip_subnet: IpSubnetV6::new(ipv6_to_in6_addr(ip), ipv6_to_in6_addr(mask)),
        },
    )
}

fn ipv4_to_in_addr(ip: Ipv4Addr) -> IN_ADDR {
    let [b1, b2, b3, b4] = ip.octets();
    IN_ADDR {
        S_un: IN_ADDR_0 {
            S_un_b: IN_ADDR_0_0 {
                s_b1: b1,
                s_b2: b2,
                s_b3: b3,
                s_b4: b4,
            },
        },
    }
}

fn ipv6_to_in6_addr(ip: Ipv6Addr) -> IN6_ADDR {
    IN6_ADDR {
        u: IN6_ADDR_0 { Byte: ip.octets() },
    }
}
