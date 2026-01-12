use super::SocksLocalRouter;
use super::packet::PortRewrite;
use log::info;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) const UDP_TIMEOUT_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub(super) struct TcpPortMapping {
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
    pub(super) proxy_port: u16,
}

#[derive(Clone, Debug)]
pub(super) struct UdpPortMapping {
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
    pub(super) proxy_port: u16,
    pub(super) last_active: Instant,
}

impl SocksLocalRouter {
    pub(super) fn get_proxy_port_tcp(&self, process_path: &str, is_v6: bool) -> u16 {
        let map = self.name_to_proxy.lock().unwrap();
        let proxies = self.proxies.lock().unwrap();
        for (name, proxy_id) in map.iter() {
            if process_path.contains(name)
                && let Some(proxy) = proxies.get(*proxy_id)
            {
                return if is_v6 {
                    proxy.get_local_tcp_proxy_port_v6()
                } else {
                    proxy.get_local_tcp_proxy_port_v4()
                };
            }
        }
        0
    }

    pub(super) fn get_proxy_port_udp(&self, process_path: &str, is_v6: bool) -> u16 {
        let map = self.name_to_proxy.lock().unwrap();
        let proxies = self.proxies.lock().unwrap();
        for (name, proxy_id) in map.iter() {
            if process_path.contains(name)
                && let Some(proxy) = proxies.get(*proxy_id)
            {
                return if is_v6 {
                    proxy.get_local_udp_proxy_port_v6()
                } else {
                    proxy.get_local_udp_proxy_port_v4()
                };
            }
        }
        0
    }

    pub(super) fn is_tcp_proxy_port(&self, port: u16) -> bool {
        let proxies = self.proxies.lock().unwrap();
        proxies.iter().any(|proxy| {
            proxy.get_local_tcp_proxy_port_v4() == port
                || proxy.get_local_tcp_proxy_port_v6() == port
        })
    }

    pub(super) fn is_udp_proxy_port(&self, port: u16) -> bool {
        let proxies = self.proxies.lock().unwrap();
        proxies.iter().any(|proxy| {
            proxy.get_local_udp_proxy_port_v4() == port
                || proxy.get_local_udp_proxy_port_v6() == port
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn process_tcp_payload(
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
            if let Ok(path) = self.process_lookup.find_process_path(false, src, dst).await {
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

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn process_udp_payload(
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

        // Check for existing UDP mapping
        {
            let mut map = self.udp_endpoints.lock().unwrap();
            if let Some(entry) = map.get(&key).cloned() {
                if entry.dst_port == dst_port {
                    if let Some(e) = map.get_mut(&key) {
                        e.last_active = now;
                    }
                    return Some(PortRewrite::ToProxy(entry.proxy_port));
                } else {
                    return None;
                }
            }
        }

        // No mapping found, perform process lookup (async, no lock held)
        if let Ok(path) = self.process_lookup.find_process_path(true, src, dst).await {
            proxy_port = self.get_proxy_port_udp(&path, is_v6);
            if proxy_port != 0 {
                let mut map = self.udp_endpoints.lock().unwrap();
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

    pub(super) fn cleanup_stale_udp_endpoints(&self) {
        let timeout = Duration::from_secs(UDP_TIMEOUT_SECS);
        let now = Instant::now();
        let mut map = self.udp_endpoints.lock().unwrap();
        map.retain(|_, entry| now.duration_since(entry.last_active) < timeout);
    }
}

pub(super) fn normalize_mapped_ipv6(addr: SocketAddr) -> SocketAddr {
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
