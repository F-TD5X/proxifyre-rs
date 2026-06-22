mod adapter;
mod filters;
mod flow;
mod packet;

use crate::proxy::{Socks5Dialer, TransparentProxy};
use crate::windows::process::{ProcessLookup, WindowsProcessLookup};
use anyhow::{Context, Result, anyhow};
use log::{error, info};
use ndisapi::{Ndisapi, StaticFilter, StaticFilterTable};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::task::{JoinHandle, spawn_local};
use windows::Win32::Foundation::{HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use self::adapter::{run_packet_loop, select_best_adapter_name};
use self::filters::{
    build_icmp_pass_filter, build_proxy_pass_filters, build_proxy_pass_filters_v6,
};
use self::flow::{TcpPortMapping, UdpFlowKey, UdpIndexKey, UdpPortMapping, normalize_mapped_ipv6};

const DRIVER_NAME: &str = "NDISRD";
const MAX_STATIC_FILTERS: usize = 256;

pub struct SocksLocalRouter {
    adapter_name: Arc<Mutex<String>>,
    process_lookup: Arc<dyn ProcessLookup>,
    #[allow(clippy::type_complexity)]
    tcp_connections: Arc<Mutex<HashMap<(IpAddr, IpAddr, u16), TcpPortMapping>>>,
    udp_endpoints: Arc<Mutex<UdpMappings>>,
    proxies: Arc<Mutex<Vec<Arc<TransparentProxy>>>>,
    name_to_proxy: Arc<Mutex<HashMap<String, usize>>>,
    static_filters: Arc<Mutex<Vec<StaticFilter>>>,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    is_active: AtomicBool,
    packet_task: Mutex<Option<JoinHandle<()>>>,
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

        let filters = vec![build_icmp_pass_filter()];

        Ok(Self {
            adapter_name: Arc::new(Mutex::new(adapter_name)),
            process_lookup: Arc::new(WindowsProcessLookup::new()),
            tcp_connections: Arc::new(Mutex::new(HashMap::new())),
            udp_endpoints: Arc::new(Mutex::new(UdpMappings::new())),
            proxies: Arc::new(Mutex::new(Vec::new())),
            name_to_proxy: Arc::new(Mutex::new(HashMap::new())),
            static_filters: Arc::new(Mutex::new(filters)),
            shutdown: Arc::new(AtomicBool::new(false)),
            restart: Arc::new(AtomicBool::new(false)),
            is_active: AtomicBool::new(false),
            packet_task: Mutex::new(None),
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
            let key = UdpFlowKey::new(peer.ip(), local_ip, peer.port());
            if !local_ip.is_unspecified() {
                return map
                    .by_flow
                    .get(&key)
                    .map(|entry| (entry.dst_ip, entry.dst_port))
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "original destination not found",
                        )
                    });
            }

            match map.by_peer.get(&UdpIndexKey::new(peer.ip(), peer.port())) {
                Some(Some(key)) => map
                    .by_flow
                    .get(key)
                    .map(|entry| (entry.dst_ip, entry.dst_port))
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "original destination not found",
                        )
                    }),
                Some(None) => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "ambiguous destination mapping",
                )),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "original destination not found",
                )),
            }
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

    pub async fn start(self: &Arc<Self>) -> Result<()> {
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
            if let Err(err) = proxy.start().await {
                self.is_active.store(false, Ordering::SeqCst);
                return Err(err.into());
            }
        }

        let adapter_name = Arc::clone(&self.adapter_name);
        let shutdown = Arc::clone(&self.shutdown);
        let restart = Arc::clone(&self.restart);
        let router = Arc::clone(self);

        let task = spawn_local(async move {
            if let Err(err) =
                run_packet_loop(DRIVER_NAME, adapter_name, shutdown, restart, router).await
            {
                error!("packet loop exited with error: {err}");
            }
        });

        *self.packet_task.lock().unwrap() = Some(task);
        self.register_interface_change_notifications();
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        if !self.is_active.swap(false, Ordering::SeqCst) {
            return Err(anyhow!("router already stopped"));
        }

        self.shutdown.store(true, Ordering::Relaxed);
        self.restart.store(false, Ordering::Relaxed);
        self.cancel_interface_change_notifications();

        let task = self.packet_task.lock().unwrap().take();
        if let Some(task) = task {
            let _ = task.await;
        }

        let proxies = self.proxies.lock().unwrap().clone();
        for proxy in proxies {
            proxy.stop().await;
        }

        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        self.stop().await?;
        self.reset_static_filters()?;
        Ok(())
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
}

impl SocksLocalRouter {
    pub fn get_tcp_connection_count(&self) -> usize {
        self.tcp_connections.lock().unwrap().len()
    }

    pub fn get_udp_connection_count(&self) -> usize {
        self.udp_endpoints.lock().unwrap().by_flow.len()
    }

    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn get_running_time(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

struct UdpMappings {
    by_flow: HashMap<UdpFlowKey, UdpPortMapping>,
    by_peer: HashMap<UdpIndexKey, Option<UdpFlowKey>>,
}

impl UdpMappings {
    fn new() -> Self {
        Self {
            by_flow: HashMap::new(),
            by_peer: HashMap::new(),
        }
    }

    fn insert(&mut self, key: UdpFlowKey, entry: UdpPortMapping) {
        let existing = self.by_flow.contains_key(&key);
        self.by_flow.insert(key, entry);
        if !existing {
            self.insert_peer_index(key);
        }
    }

    fn retain_active(&mut self, mut keep: impl FnMut(&UdpPortMapping) -> bool) {
        self.by_flow.retain(|_, entry| keep(entry));
        self.rebuild_peer_index();
    }

    fn rebuild_peer_index(&mut self) {
        self.by_peer.clear();
        let by_peer = &mut self.by_peer;
        for key in self.by_flow.keys().copied() {
            insert_peer_index(by_peer, key);
        }
    }

    fn insert_peer_index(&mut self, key: UdpFlowKey) {
        insert_peer_index(&mut self.by_peer, key);
    }
}

fn insert_peer_index(by_peer: &mut HashMap<UdpIndexKey, Option<UdpFlowKey>>, key: UdpFlowKey) {
    let index_key = UdpIndexKey::new(key.dst_ip, key.src_port);
    by_peer
        .entry(index_key)
        .and_modify(|entry| {
            if *entry != Some(key) {
                *entry = None;
            }
        })
        .or_insert(Some(key));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn udp_entry(dst_ip: IpAddr, dst_port: u16) -> UdpPortMapping {
        UdpPortMapping {
            dst_ip,
            dst_port,
            proxy_port: 10000,
            last_active: Instant::now(),
        }
    }

    #[test]
    fn udp_peer_index_tracks_unique_mapping() {
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let key = UdpFlowKey::new(dst, src, 53000);
        let mut mappings = UdpMappings::new();

        mappings.insert(key, udp_entry(dst, 53));

        assert_eq!(
            mappings.by_peer.get(&UdpIndexKey::new(dst, 53000)),
            Some(&Some(key))
        );
    }

    #[test]
    fn udp_peer_index_marks_ambiguous_mapping() {
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let src_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let src_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let mut mappings = UdpMappings::new();

        mappings.insert(UdpFlowKey::new(dst, src_a, 53000), udp_entry(dst, 53));
        mappings.insert(UdpFlowKey::new(dst, src_b, 53000), udp_entry(dst, 53));

        assert_eq!(
            mappings.by_peer.get(&UdpIndexKey::new(dst, 53000)),
            Some(&None)
        );
    }

    #[test]
    fn udp_peer_index_rebuilds_after_cleanup() {
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let src_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let src_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let key_a = UdpFlowKey::new(dst, src_a, 53000);
        let key_b = UdpFlowKey::new(dst, src_b, 53000);
        let mut mappings = UdpMappings::new();

        mappings.insert(key_a, udp_entry(dst, 53));
        mappings.insert(key_b, udp_entry(dst, 123));
        mappings.retain_active(|entry| entry.dst_port == 53);

        assert_eq!(
            mappings.by_peer.get(&UdpIndexKey::new(dst, 53000)),
            Some(&Some(key_a))
        );
    }
}

unsafe extern "system" fn ip_interface_changed_callback(
    callercontext: *const c_void,
    _row: *const windows::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW,
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
