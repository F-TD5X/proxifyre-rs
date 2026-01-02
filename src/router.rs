use crate::proxy::{Socks5Dialer, TransparentProxy};
use crate::windows::process::ProcessLookup;
use anyhow::{Context, Result, anyhow};
use log::{error, info};
use ndisapi::{
    DataLinkLayerFilter, DirectionFlags, EthRequest, EthRequestMut, FILTER_PACKET_PASS,
    FilterFlags, FilterLayerFlags, IP_SUBNET_V4_TYPE, IP_SUBNET_V6_TYPE, IPV4, IPV6,
    IntermediateBuffer, IpAddressV4, IpAddressV4Union, IpAddressV6, IpAddressV6Union, IpSubnetV4,
    IpSubnetV6, IpV4Filter, IpV4FilterFlags, IpV6Filter, IpV6FilterFlags, IphlpNetworkAdapterInfo,
    MacAddress, Ndisapi, NetworkLayerFilter, NetworkLayerFilterUnion, PortRange, StaticFilter,
    StaticFilterTable, TCPUDP, TcpUdpFilter, TcpUdpFilterFlags, TransportLayerFilter,
    TransportLayerFilterUnion,
};
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
    Ipv6Packet, TcpPacket, UdpPacket,
};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GetBestInterface, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    NotifyIpInterfaceChange,
};
use windows::Win32::Networking::WinSock::{
    AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, IN6_ADDR, IN6_ADDR_0,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

const DRIVER_NAME: &str = "NDISRD";
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const MAX_STATIC_FILTERS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyDirection {
    ToProxy,
    FromProxy,
}

#[derive(Clone, Copy, Debug)]
enum PortRewrite {
    ToProxy(u16),
    FromProxy(u16),
}

#[derive(Clone, Debug)]
struct TcpPortMapping {
    dst_ip: IpAddr,
    dst_port: u16,
    proxy_port: u16,
}

#[derive(Clone, Debug)]
struct UdpPortMapping {
    dst_ip: IpAddr,
    dst_port: u16,
    proxy_port: u16,
    last_active: Instant,
}

const UDP_TIMEOUT_SECS: u64 = 60;

pub struct SocksLocalRouter {
    adapter_name: Arc<Mutex<String>>,
    process_lookup: ProcessLookup,
    tcp_connections: Arc<Mutex<HashMap<(IpAddr, IpAddr, u16), TcpPortMapping>>>,
    udp_endpoints: Arc<Mutex<HashMap<(IpAddr, IpAddr, u16), UdpPortMapping>>>,
    proxies: Arc<Mutex<Vec<Arc<TransparentProxy>>>>,
    name_to_proxy: Arc<Mutex<HashMap<String, usize>>>,
    static_filters: Arc<Mutex<Vec<StaticFilter>>>,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    is_active: AtomicBool,
    packet_thread: Mutex<Option<JoinHandle<()>>>,
    notify_handle: Mutex<Option<usize>>,
    notify_context: Mutex<Option<usize>>,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub start_time: Instant,
}

impl SocksLocalRouter {
    pub fn new(driver: &Ndisapi) -> Result<Self> {
        let adapter_name = select_best_adapter_name(driver)?;
        let friendly = Ndisapi::get_friendly_adapter_name(&adapter_name)
            .unwrap_or_else(|_| adapter_name.clone());
        info!("Using adapter: {}", friendly);

        let mut filters = Vec::new();
        filters.push(build_icmp_pass_filter());

        Ok(Self {
            adapter_name: Arc::new(Mutex::new(adapter_name)),
            process_lookup: ProcessLookup::new(),
            tcp_connections: Arc::new(Mutex::new(HashMap::new())),
            udp_endpoints: Arc::new(Mutex::new(HashMap::new())),
            proxies: Arc::new(Mutex::new(Vec::new())),
            name_to_proxy: Arc::new(Mutex::new(HashMap::new())),
            static_filters: Arc::new(Mutex::new(filters)),
            shutdown: Arc::new(AtomicBool::new(false)),
            restart: Arc::new(AtomicBool::new(false)),
            is_active: AtomicBool::new(false),
            packet_thread: Mutex::new(None),
            notify_handle: Mutex::new(None),
            notify_context: Mutex::new(None),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
        })
    }

    pub fn add_socks5_proxy(&self, endpoint: &str) -> Result<usize> {
        let dialer = Socks5Dialer::new(endpoint)
            .with_context(|| format!("failed to parse SOCKS5 endpoint: {endpoint}"))?;
        let proxy_addr = dialer.proxy_addr();

        match proxy_addr.ip() {
            IpAddr::V4(ipv4) => {
                let mut filters = self.static_filters.lock().unwrap();
                filters.extend(build_proxy_pass_filters(ipv4, proxy_addr.port()));
            }
            IpAddr::V6(ipv6) => {
                let mut filters = self.static_filters.lock().unwrap();
                filters.extend(build_proxy_pass_filters_v6(ipv6, proxy_addr.port()));
            }
        }

        let tcp_map = Arc::clone(&self.tcp_connections);
        let udp_map = Arc::clone(&self.udp_endpoints);

        let query_tcp = Arc::new(move |peer: SocketAddr, local: SocketAddr| {
            let peer = normalize_mapped_ipv6(peer);
            let local = normalize_mapped_ipv6(local);
            let key = (peer.ip(), local.ip(), peer.port());
            let map = tcp_map.lock().unwrap();
            map.get(&key)
                .map(|entry| (entry.dst_ip, entry.dst_port))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "original destination not found",
                    )
                })
        });

        let query_udp = Arc::new(move |peer: SocketAddr, local: SocketAddr| {
            let peer = normalize_mapped_ipv6(peer);
            let local = normalize_mapped_ipv6(local);
            let map = udp_map.lock().unwrap();
            let local_ip = local.ip();
            let key = (peer.ip(), local_ip, peer.port());
            if !local_ip.is_unspecified() {
                return map
                    .get(&key)
                    .map(|entry| (entry.dst_ip, entry.dst_port))
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "original destination not found",
                        )
                    });
            }

            let mut match_entry = None;
            for ((dst_ip, _src_ip, src_port), entry) in map.iter() {
                if *dst_ip == peer.ip() && *src_port == peer.port() {
                    if match_entry.is_some() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "ambiguous destination mapping",
                        ));
                    }
                    match_entry = Some(entry);
                }
            }

            match_entry
                .map(|entry| (entry.dst_ip, entry.dst_port))
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "original destination not found",
                    )
                })
        });

        let proxy = Arc::new(TransparentProxy::new(0, dialer, query_tcp, query_udp));
        let mut proxies = self.proxies.lock().unwrap();
        proxies.push(proxy);

        self.apply_static_filters()?;
        Ok(proxies.len() - 1)
    }

    pub fn associate_process_name_to_proxy(
        &self,
        process_name: &str,
        proxy_id: usize,
    ) -> Result<()> {
        let proxies = self.proxies.lock().unwrap();
        if proxy_id >= proxies.len() {
            return Err(anyhow!("proxy index is out of range"));
        }
        drop(proxies);

        let mut map = self.name_to_proxy.lock().unwrap();
        map.insert(process_name.to_string(), proxy_id);
        Ok(())
    }

    pub fn start(self: &Arc<Self>) -> Result<()> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(anyhow!("router already stopped"));
        }
        if self.is_active.swap(true, Ordering::SeqCst) {
            return Err(anyhow!("router already active"));
        }

        if let Err(err) = self.apply_static_filters() {
            self.is_active.store(false, Ordering::SeqCst);
            return Err(err);
        }

        let proxies = self.proxies.lock().unwrap().clone();
        for proxy in proxies {
            if let Err(err) = proxy.start() {
                self.is_active.store(false, Ordering::SeqCst);
                return Err(err.into());
            }
        }

        let adapter_name = Arc::clone(&self.adapter_name);
        let shutdown = Arc::clone(&self.shutdown);
        let restart = Arc::clone(&self.restart);
        let router = Arc::clone(self);

        let thread = thread::spawn(move || {
            if let Err(err) = run_packet_loop(DRIVER_NAME, adapter_name, shutdown, restart, router)
            {
                error!("packet loop exited with error: {err}");
            }
        });

        *self.packet_thread.lock().unwrap() = Some(thread);
        self.register_interface_change_notifications();
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        if !self.is_active.swap(false, Ordering::SeqCst) {
            return Err(anyhow!("router already stopped"));
        }

        self.shutdown.store(true, Ordering::Relaxed);
        self.restart.store(false, Ordering::Relaxed);
        self.cancel_interface_change_notifications();

        if let Some(thread) = self.packet_thread.lock().unwrap().take() {
            let _ = thread.join();
        }

        let proxies = self.proxies.lock().unwrap().clone();
        for proxy in proxies {
            proxy.stop();
        }

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        self.stop()?;
        self.reset_static_filters()?;
        Ok(())
    }

    fn get_proxy_port_tcp(&self, process_path: &str, is_v6: bool) -> u16 {
        let map = self.name_to_proxy.lock().unwrap();
        let proxies = self.proxies.lock().unwrap();
        for (name, proxy_id) in map.iter() {
            if process_path.contains(name) {
                if let Some(proxy) = proxies.get(*proxy_id) {
                    return if is_v6 {
                        proxy.get_local_tcp_proxy_port_v6()
                    } else {
                        proxy.get_local_tcp_proxy_port_v4()
                    };
                }
            }
        }
        0
    }

    fn get_proxy_port_udp(&self, process_path: &str, is_v6: bool) -> u16 {
        let map = self.name_to_proxy.lock().unwrap();
        let proxies = self.proxies.lock().unwrap();
        for (name, proxy_id) in map.iter() {
            if process_path.contains(name) {
                if let Some(proxy) = proxies.get(*proxy_id) {
                    return if is_v6 {
                        proxy.get_local_udp_proxy_port_v6()
                    } else {
                        proxy.get_local_udp_proxy_port_v4()
                    };
                }
            }
        }
        0
    }

    fn is_tcp_proxy_port(&self, port: u16) -> bool {
        let proxies = self.proxies.lock().unwrap();
        proxies.iter().any(|proxy| {
            proxy.get_local_tcp_proxy_port_v4() == port
                || proxy.get_local_tcp_proxy_port_v6() == port
        })
    }

    fn is_udp_proxy_port(&self, port: u16) -> bool {
        let proxies = self.proxies.lock().unwrap();
        proxies.iter().any(|proxy| {
            proxy.get_local_udp_proxy_port_v4() == port
                || proxy.get_local_udp_proxy_port_v6() == port
        })
    }

    fn apply_static_filters(&self) -> Result<()> {
        let filters = self.static_filters.lock().unwrap().clone();
        if filters.is_empty() {
            return self.reset_static_filters();
        }
        if filters.len() > MAX_STATIC_FILTERS {
            return Err(anyhow!(
                "too many static filters: {} (max {MAX_STATIC_FILTERS})",
                filters.len()
            ));
        }

        let mut table = StaticFilterTable::<MAX_STATIC_FILTERS>::new();
        table.table_size = filters.len() as u32;
        for (idx, filter) in filters.into_iter().enumerate() {
            table.static_filters[idx] = filter;
        }

        let driver = Ndisapi::new(DRIVER_NAME).context("failed to open NDIS driver")?;
        driver
            .set_packet_filter_table(&table)
            .context("failed to set static filter table")?;
        Ok(())
    }

    fn reset_static_filters(&self) -> Result<()> {
        let driver = Ndisapi::new(DRIVER_NAME).context("failed to open NDIS driver")?;
        driver
            .reset_packet_filter_table()
            .context("failed to reset static filter table")?;
        Ok(())
    }

    fn register_interface_change_notifications(self: &Arc<Self>) {
        let mut handle_slot = self.notify_handle.lock().unwrap();
        if handle_slot.is_some() {
            return;
        }

        let ctx = Arc::into_raw(Arc::clone(self)) as *const c_void;
        let mut handle = HANDLE::default();
        let status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(ip_interface_changed_callback),
                Some(ctx),
                false,
                &mut handle,
            )
        };

        if status != NO_ERROR {
            unsafe {
                let _ = Arc::from_raw(ctx as *const SocksLocalRouter);
            }
            error!("NotifyIpInterfaceChange failed: {status:?}");
            return;
        }

        *handle_slot = Some(handle.0 as usize);
        *self.notify_context.lock().unwrap() = Some(ctx as usize);
    }

    fn cancel_interface_change_notifications(&self) {
        if let Some(handle) = self.notify_handle.lock().unwrap().take() {
            let handle = HANDLE(handle as *mut c_void);
            unsafe {
                let _ = CancelMibChangeNotify2(handle);
            }
        }

        if let Some(ctx) = self.notify_context.lock().unwrap().take() {
            unsafe {
                let _ = Arc::from_raw(ctx as *const SocksLocalRouter);
            }
        }
    }

    fn refresh_adapter_name(&self) -> Result<bool> {
        let driver = Ndisapi::new(DRIVER_NAME).context("failed to open NDIS driver")?;
        let new_name = select_best_adapter_name(&driver)?;
        let mut name = self.adapter_name.lock().unwrap();
        if *name != new_name {
            let friendly =
                Ndisapi::get_friendly_adapter_name(&new_name).unwrap_or_else(|_| new_name.clone());
            info!("Detected default interface: {}", friendly);
            *name = new_name;
            return Ok(true);
        }
        Ok(false)
    }

    fn process_packet(&self, packet: &mut IntermediateBuffer) -> Option<ProxyDirection> {
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
            EthernetProtocol::Ipv4 => self.process_ipv4(&mut frame),
            EthernetProtocol::Ipv6 => self.process_ipv6(&mut frame),
            _ => None,
        }
    }

    fn process_ipv4(&self, frame: &mut EthernetFrame<&mut [u8]>) -> Option<ProxyDirection> {
        let mut ipv4 = match Ipv4Packet::new_checked(frame.payload_mut()) {
            Ok(pkt) => pkt,
            Err(_) => return None,
        };

        let src_ip = ipv4.src_addr();
        let dst_ip = ipv4.dst_addr();

        match ipv4.next_header() {
            IpProtocol::Tcp => {
                let direction = {
                    let mut tcp = match TcpPacket::new_checked(ipv4.payload_mut()) {
                        Ok(pkt) => pkt,
                        Err(_) => return None,
                    };
                    self.process_tcp_v4_payload(src_ip, dst_ip, &mut tcp)
                };

                if direction.is_some() {
                    swap_ipv4(&mut ipv4);
                    let src = ipv4.src_addr();
                    let dst = ipv4.dst_addr();
                    if let Ok(mut tcp) = TcpPacket::new_checked(ipv4.payload_mut()) {
                        tcp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
                    }
                    ipv4.fill_checksum();
                    swap_mac(frame);
                }
                direction
            }
            IpProtocol::Udp => {
                if dst_ip.is_multicast() || dst_ip.is_broadcast() {
                    return None;
                }

                let direction = {
                    let mut udp = match UdpPacket::new_checked(ipv4.payload_mut()) {
                        Ok(pkt) => pkt,
                        Err(_) => return None,
                    };
                    self.process_udp_v4_payload(src_ip, dst_ip, &mut udp)
                };

                if direction.is_some() {
                    swap_ipv4(&mut ipv4);
                    let src = ipv4.src_addr();
                    let dst = ipv4.dst_addr();
                    if let Ok(mut udp) = UdpPacket::new_checked(ipv4.payload_mut()) {
                        udp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
                    }
                    ipv4.fill_checksum();
                    swap_mac(frame);
                }
                direction
            }
            _ => None,
        }
    }

    fn process_ipv6(&self, frame: &mut EthernetFrame<&mut [u8]>) -> Option<ProxyDirection> {
        let mut ipv6 = match Ipv6Packet::new_checked(frame.payload_mut()) {
            Ok(pkt) => pkt,
            Err(_) => return None,
        };

        let src_ip = ipv6.src_addr();
        let dst_ip = ipv6.dst_addr();

        match ipv6.next_header() {
            IpProtocol::Tcp => {
                let direction = {
                    let mut tcp = match TcpPacket::new_checked(ipv6.payload_mut()) {
                        Ok(pkt) => pkt,
                        Err(_) => return None,
                    };
                    self.process_tcp_v6_payload(src_ip, dst_ip, &mut tcp)
                };

                if direction.is_some() {
                    swap_ipv6(&mut ipv6);
                    let src = ipv6.src_addr();
                    let dst = ipv6.dst_addr();
                    if let Ok(mut tcp) = TcpPacket::new_checked(ipv6.payload_mut()) {
                        tcp.fill_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst));
                    }
                    swap_mac(frame);
                }
                direction
            }
            IpProtocol::Udp => {
                if dst_ip.is_multicast() {
                    return None;
                }

                let direction = {
                    let mut udp = match UdpPacket::new_checked(ipv6.payload_mut()) {
                        Ok(pkt) => pkt,
                        Err(_) => return None,
                    };
                    self.process_udp_v6_payload(src_ip, dst_ip, &mut udp)
                };

                if direction.is_some() {
                    swap_ipv6(&mut ipv6);
                    let src = ipv6.src_addr();
                    let dst = ipv6.dst_addr();
                    if let Ok(mut udp) = UdpPacket::new_checked(ipv6.payload_mut()) {
                        udp.fill_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst));
                    }
                    swap_mac(frame);
                }
                direction
            }
            _ => None,
        }
    }

    fn process_tcp_v4_payload(
        &self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        tcp: &mut TcpPacket<&mut [u8]>,
    ) -> Option<ProxyDirection> {
        let src_ip_std = IpAddr::V4(Ipv4Addr::from(src_ip));
        let dst_ip_std = IpAddr::V4(Ipv4Addr::from(dst_ip));
        let src_port = tcp.src_port();
        let dst_port = tcp.dst_port();

        let src = SocketAddr::new(src_ip_std, src_port);
        let dst = SocketAddr::new(dst_ip_std, dst_port);
        let rewrite = self.process_tcp_payload(
            "TCP",
            src,
            dst,
            src_ip_std,
            dst_ip_std,
            src_port,
            dst_port,
            false,
            tcp.syn(),
            tcp.ack(),
            tcp.rst(),
            tcp.fin(),
        );
        match rewrite {
            Some(PortRewrite::ToProxy(port)) => {
                tcp.set_dst_port(port);
                Some(ProxyDirection::ToProxy)
            }
            Some(PortRewrite::FromProxy(port)) => {
                tcp.set_src_port(port);
                Some(ProxyDirection::FromProxy)
            }
            None => None,
        }
    }

    fn process_tcp_v6_payload(
        &self,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        tcp: &mut TcpPacket<&mut [u8]>,
    ) -> Option<ProxyDirection> {
        let src_ip_std = IpAddr::V6(Ipv6Addr::from(src_ip));
        let dst_ip_std = IpAddr::V6(Ipv6Addr::from(dst_ip));
        let src_port = tcp.src_port();
        let dst_port = tcp.dst_port();

        let src = SocketAddr::new(src_ip_std, src_port);
        let dst = SocketAddr::new(dst_ip_std, dst_port);
        let rewrite = self.process_tcp_payload(
            "TCPv6",
            src,
            dst,
            src_ip_std,
            dst_ip_std,
            src_port,
            dst_port,
            true,
            tcp.syn(),
            tcp.ack(),
            tcp.rst(),
            tcp.fin(),
        );
        match rewrite {
            Some(PortRewrite::ToProxy(port)) => {
                tcp.set_dst_port(port);
                Some(ProxyDirection::ToProxy)
            }
            Some(PortRewrite::FromProxy(port)) => {
                tcp.set_src_port(port);
                Some(ProxyDirection::FromProxy)
            }
            None => None,
        }
    }

    fn process_udp_v4_payload(
        &self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        udp: &mut UdpPacket<&mut [u8]>,
    ) -> Option<ProxyDirection> {
        let src_ip_std = IpAddr::V4(Ipv4Addr::from(src_ip));
        let dst_ip_std = IpAddr::V4(Ipv4Addr::from(dst_ip));
        let src_port = udp.src_port();
        let dst_port = udp.dst_port();

        let src = SocketAddr::new(src_ip_std, src_port);
        let dst = SocketAddr::new(dst_ip_std, dst_port);
        let rewrite = self.process_udp_payload(
            "UDP", src, dst, src_ip_std, dst_ip_std, src_port, dst_port, false,
        );
        match rewrite {
            Some(PortRewrite::ToProxy(port)) => {
                udp.set_dst_port(port);
                Some(ProxyDirection::ToProxy)
            }
            Some(PortRewrite::FromProxy(port)) => {
                udp.set_src_port(port);
                Some(ProxyDirection::FromProxy)
            }
            None => None,
        }
    }

    fn process_udp_v6_payload(
        &self,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        udp: &mut UdpPacket<&mut [u8]>,
    ) -> Option<ProxyDirection> {
        let src_ip_std = IpAddr::V6(Ipv6Addr::from(src_ip));
        let dst_ip_std = IpAddr::V6(Ipv6Addr::from(dst_ip));
        let src_port = udp.src_port();
        let dst_port = udp.dst_port();

        let src = SocketAddr::new(src_ip_std, src_port);
        let dst = SocketAddr::new(dst_ip_std, dst_port);
        let rewrite = self.process_udp_payload(
            "UDPv6", src, dst, src_ip_std, dst_ip_std, src_port, dst_port, true,
        );
        match rewrite {
            Some(PortRewrite::ToProxy(port)) => {
                udp.set_dst_port(port);
                Some(ProxyDirection::ToProxy)
            }
            Some(PortRewrite::FromProxy(port)) => {
                udp.set_src_port(port);
                Some(ProxyDirection::FromProxy)
            }
            None => None,
        }
    }

    fn process_tcp_payload(
        &self,
        label: &str,
        src: SocketAddr,
        dst: SocketAddr,
        src_ip_std: IpAddr,
        dst_ip_std: IpAddr,
        src_port: u16,
        dst_port: u16,
        is_v6: bool,
        syn: bool,
        ack: bool,
        rst: bool,
        fin: bool,
    ) -> Option<PortRewrite> {
        let mut redirected = false;
        let mut proxy_port = 0u16;

        if syn && !ack {
            if let Ok(path) = self.process_lookup.find_process_path(false, src, dst) {
                proxy_port = self.get_proxy_port_tcp(&path, is_v6);
                if proxy_port != 0 {
                    let key = (dst_ip_std, src_ip_std, src_port);
                    let mut map = self.tcp_connections.lock().unwrap();
                    map.entry(key).or_insert(TcpPortMapping {
                        dst_ip: dst_ip_std,
                        dst_port,
                        proxy_port,
                    });
                    redirected = true;
                    let process_label = format_process_label(&path);
                    info!(
                        "[{}] [PROXY] {} {} -> {} (redirect to {})",
                        label, process_label, src, dst, proxy_port
                    );
                }
            }
        } else {
            let key = (dst_ip_std, src_ip_std, src_port);
            let mut map = self.tcp_connections.lock().unwrap();
            if let Some(entry) = map.get(&key).cloned() {
                if rst || fin {
                    map.remove(&key);
                    info!("[{}] {} -> {} (closed)", label, src, dst);
                }
                proxy_port = entry.proxy_port;
                redirected = true;
            }
        }

        if redirected {
            return Some(PortRewrite::ToProxy(proxy_port));
        }

        if self.is_tcp_proxy_port(src_port) {
            let key = (dst_ip_std, src_ip_std, dst_port);
            let mut map = self.tcp_connections.lock().unwrap();
            if let Some(entry) = map.get(&key).cloned() {
                if rst || fin {
                    map.remove(&key);
                    info!("[{}] {} -> {} (closed)", label, src, dst);
                }
                return Some(PortRewrite::FromProxy(entry.dst_port));
            }
        }

        None
    }

    fn process_udp_payload(
        &self,
        label: &str,
        src: SocketAddr,
        dst: SocketAddr,
        src_ip_std: IpAddr,
        dst_ip_std: IpAddr,
        src_port: u16,
        dst_port: u16,
        is_v6: bool,
    ) -> Option<PortRewrite> {
        let mut redirected = false;
        let mut proxy_port = 0u16;
        let now = Instant::now();

        let key = (dst_ip_std, src_ip_std, src_port);
        {
            let mut map = self.udp_endpoints.lock().unwrap();
            if let Some(entry) = map.get(&key).cloned() {
                if entry.dst_port == dst_port {
                    redirected = true;
                    proxy_port = entry.proxy_port;
                    if let Some(e) = map.get_mut(&key) {
                        e.last_active = now;
                    }
                } else {
                    return None;
                }
            } else if let Ok(path) = self.process_lookup.find_process_path(true, src, dst) {
                proxy_port = self.get_proxy_port_udp(&path, is_v6);
                if proxy_port != 0 {
                    map.insert(
                        key,
                        UdpPortMapping {
                            dst_ip: dst_ip_std,
                            dst_port,
                            proxy_port,
                            last_active: now,
                        },
                    );
                    redirected = true;
                    let process_label = format_process_label(&path);
                    info!(
                        "[{}] [PROXY] {} {} -> {} (redirect to {})",
                        label, process_label, src, dst, proxy_port
                    );
                }
            }
        }

        if redirected {
            return Some(PortRewrite::ToProxy(proxy_port));
        }

        if self.is_udp_proxy_port(src_port) {
            let key = (dst_ip_std, src_ip_std, dst_port);
            let map = self.udp_endpoints.lock().unwrap();
            if let Some(entry) = map.get(&key).cloned() {
                return Some(PortRewrite::FromProxy(entry.dst_port));
            }
        }

        None
    }

    fn cleanup_stale_udp_endpoints(&self) {
        let timeout = Duration::from_secs(UDP_TIMEOUT_SECS);
        let now = Instant::now();
        let mut map = self.udp_endpoints.lock().unwrap();
        map.retain(|_, entry| now.duration_since(entry.last_active) < timeout);
    }
}

impl SocksLocalRouter {
    pub fn get_tcp_connection_count(&self) -> usize {
        self.tcp_connections.lock().unwrap().len()
    }

    pub fn get_udp_connection_count(&self) -> usize {
        self.udp_endpoints.lock().unwrap().len()
    }

    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn get_running_time(&self) -> Duration {
        self.start_time.elapsed()
    }
}

unsafe extern "system" fn ip_interface_changed_callback(
    callercontext: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _notificationtype: MIB_NOTIFICATION_TYPE,
) {
    if callercontext.is_null() {
        return;
    }

    let router = unsafe { &*(callercontext as *const SocksLocalRouter) };
    match router.refresh_adapter_name() {
        Ok(true) => {
            router.restart.store(true, Ordering::Relaxed);
        }
        Ok(false) => {}
        Err(err) => {
            error!("Failed to refresh adapter name: {err}");
        }
    }
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

fn build_icmp_pass_filter() -> StaticFilter {
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

fn build_proxy_pass_filters(ip: Ipv4Addr, port: u16) -> Vec<StaticFilter> {
    let dest = ipv4_subnet_filter(ip, Ipv4Addr::new(255, 255, 255, 255));
    build_proxy_pass_filters_common(dest, port, build_proxy_pass_filter)
}

fn build_proxy_pass_filters_v6(ip: Ipv6Addr, port: u16) -> Vec<StaticFilter> {
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

fn run_packet_loop(
    driver_name: &str,
    adapter_name: Arc<Mutex<String>>,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    router: Arc<SocksLocalRouter>,
) -> Result<()> {
    loop {
        let adapter_name = adapter_name.lock().unwrap().clone();
        let driver = Ndisapi::new(driver_name)?;
        let adapter_handle = match find_adapter_handle(&driver, &adapter_name) {
            Ok(handle) => handle,
            Err(err) => {
                error!("adapter not found ({adapter_name}): {err}");
                if shutdown.load(Ordering::Relaxed) {
                    return Ok(());
                }
                thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
        };

        let event: HANDLE = unsafe { CreateEventW(None, true, false, None)? };
        driver.set_packet_event(adapter_handle, event)?;
        driver.set_adapter_mode(adapter_handle, FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)?;

        let mut packet = IntermediateBuffer::default();
        let mut cleanup_counter = 0u32;

        while !shutdown.load(Ordering::Relaxed) {
            if restart.swap(false, Ordering::Relaxed) {
                break;
            }

            unsafe {
                WaitForSingleObject(event, 50);
            }

            loop {
                let mut request = EthRequestMut::new(adapter_handle);
                request.set_packet(&mut packet);
                if driver.read_packet(&mut request).is_err() {
                    break;
                }

                let proxy_direction = router.process_packet(&mut packet);
                let direction = packet.get_device_flags();
                let is_send = direction.contains(DirectionFlags::PACKET_FLAG_ON_SEND);
                let redirected = proxy_direction.is_some();
                let send_to_adapter = if redirected { !is_send } else { is_send };

                let length = packet.get_length() as u64;
                if let Some(proxy_direction) = proxy_direction {
                    match proxy_direction {
                        ProxyDirection::ToProxy => {
                            router.bytes_sent.fetch_add(length, Ordering::Relaxed);
                        }
                        ProxyDirection::FromProxy => {
                            router.bytes_received.fetch_add(length, Ordering::Relaxed);
                        }
                    }
                }

                let mut write_request = EthRequest::new(adapter_handle);
                write_request.set_packet(&packet);

                if send_to_adapter {
                    let _ = driver.send_packet_to_adapter(&write_request);
                } else {
                    let _ = driver.send_packet_to_mstcp(&write_request);
                }
            }

            cleanup_counter += 1;
            if cleanup_counter >= 20 {
                cleanup_counter = 0;
                router.cleanup_stale_udp_endpoints();
            }

            unsafe {
                let _ = ResetEvent(event);
            }
        }

        driver
            .set_adapter_mode(adapter_handle, FilterFlags::default())
            .ok();
        unsafe {
            let _ = CloseHandle(event);
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }
    }

    Ok(())
}

fn select_best_adapter_name(driver: &Ndisapi) -> Result<String> {
    let mut adapters = driver.get_tcpip_bound_adapters_info()?;
    if adapters.is_empty() {
        return Err(anyhow!("no network adapters found"));
    }

    let best_index = get_best_interface_index();
    if let Some(index) = best_index {
        let mut mac_to_index = HashMap::new();
        for info in IphlpNetworkAdapterInfo::get_external_network_connections() {
            mac_to_index.insert(*info.physical_address(), info.if_index());
        }
        if let Some(pos) = adapters.iter().position(|adapter| {
            MacAddress::from_slice(adapter.get_hw_address())
                .and_then(|mac| mac_to_index.get(&mac).copied())
                .map(|if_index| if_index == index)
                .unwrap_or(false)
        }) {
            let adapter = adapters.remove(pos);
            return Ok(adapter.get_name().to_string());
        }
    }

    Ok(adapters.remove(0).get_name().to_string())
}

fn find_adapter_handle(driver: &Ndisapi, adapter_name: &str) -> Result<HANDLE> {
    let adapters = driver.get_tcpip_bound_adapters_info()?;
    for adapter in adapters {
        if adapter.get_name() == adapter_name {
            return Ok(adapter.get_handle());
        }
    }
    Err(anyhow!("adapter not found: {adapter_name}"))
}

fn get_best_interface_index() -> Option<u32> {
    let dest = u32::from_be_bytes([8, 8, 8, 8]);
    let mut index = 0u32;
    let res = unsafe { GetBestInterface(dest, &mut index) };
    if res == NO_ERROR.0 { Some(index) } else { None }
}

fn normalize_mapped_ipv6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|v4| SocketAddr::new(IpAddr::V4(v4), v6.port()))
            .unwrap_or(SocketAddr::V6(v6)),
        SocketAddr::V4(_) => addr,
    }
}

fn format_process_label(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .unwrap_or_else(|| path.to_string())
}
