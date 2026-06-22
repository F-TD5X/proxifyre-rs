use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task;
use windows::Win32::Foundation::{CloseHandle, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_CLASS, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_CLASS, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

#[async_trait::async_trait]
pub trait ProcessLookup: Send + Sync {
    async fn find_process_path(
        &self,
        is_udp: bool,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<String>;
}

#[derive(Clone, Default)]
pub struct WindowsProcessLookup {
    cache: Arc<Mutex<HashMap<u32, CachedProcess>>>,
    session_cache: Arc<Mutex<SessionCache>>,
}

const PROCESS_CACHE_TTL: Duration = Duration::from_secs(300);
const PROCESS_CACHE_MAX: usize = 1024;
const SESSION_CACHE_MAX_AGE: Duration = Duration::from_millis(500);

#[derive(Clone)]
struct CachedProcess {
    path: String,
    last_seen: Instant,
}

#[derive(Default)]
struct SessionCache {
    tcp_v4: HashMap<TcpKeyV4, u32>,
    tcp_v6: HashMap<TcpKeyV6, u32>,
    udp_v4: HashMap<UdpKeyV4, u32>,
    udp_v6: HashMap<UdpKeyV6, u32>,
    tcp_v4_last_refresh: Option<Instant>,
    tcp_v6_last_refresh: Option<Instant>,
    udp_v4_last_refresh: Option<Instant>,
    udp_v6_last_refresh: Option<Instant>,
}

type TcpKeyV4 = (Ipv4Addr, Ipv4Addr, u16, u16);
type TcpKeyV6 = (Ipv6Addr, Ipv6Addr, u16, u16);
type UdpKeyV4 = (Ipv4Addr, u16);
type UdpKeyV6 = (Ipv6Addr, u16);

impl WindowsProcessLookup {
    pub fn new() -> Self {
        Self::default()
    }

    fn find_process_path_sync(
        &self,
        is_udp: bool,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<String> {
        let pid = if is_udp {
            match (src, dst) {
                (SocketAddr::V4(local), _) => self.find_pid_udp_v4_cached(local),
                (SocketAddr::V6(local), _) => self.find_pid_udp_v6_cached(local),
            }
        } else {
            match (src, dst) {
                (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
                    self.find_pid_tcp_v4_cached(local, remote)
                }
                (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
                    self.find_pid_tcp_v6_cached(local, remote)
                }
                _ => None,
            }
        };

        let pid = pid.context("process id not found")?;

        let now = Instant::now();
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get_mut(&pid) {
                if now.duration_since(entry.last_seen) <= PROCESS_CACHE_TTL {
                    entry.last_seen = now;
                    return Ok(entry.path.clone());
                }
                cache.remove(&pid);
            }
        }

        let path = query_process_path(pid)?;
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            pid,
            CachedProcess {
                path: path.clone(),
                last_seen: now,
            },
        );
        if cache.len() > PROCESS_CACHE_MAX {
            cache.retain(|_, entry| now.duration_since(entry.last_seen) <= PROCESS_CACHE_TTL);
            if cache.len() > PROCESS_CACHE_MAX {
                cache.clear();
            }
        }
        Ok(path)
    }

    fn find_pid_tcp_v4_cached(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<u32> {
        if self.is_tcp_v4_stale() {
            self.refresh_tcp_v4_cache()?;
            return self.lookup_tcp_v4(local, remote);
        }
        if let Some(pid) = self.lookup_tcp_v4(local, remote) {
            return Some(pid);
        }
        self.refresh_tcp_v4_cache()?;
        self.lookup_tcp_v4(local, remote)
    }

    fn find_pid_tcp_v6_cached(&self, local: SocketAddrV6, remote: SocketAddrV6) -> Option<u32> {
        if self.is_tcp_v6_stale() {
            self.refresh_tcp_v6_cache()?;
            return self.lookup_tcp_v6(local, remote);
        }
        if let Some(pid) = self.lookup_tcp_v6(local, remote) {
            return Some(pid);
        }
        self.refresh_tcp_v6_cache()?;
        self.lookup_tcp_v6(local, remote)
    }

    fn find_pid_udp_v4_cached(&self, local: SocketAddrV4) -> Option<u32> {
        if self.is_udp_v4_stale() {
            self.refresh_udp_v4_cache()?;
            return self.lookup_udp_v4(local);
        }
        if let Some(pid) = self.lookup_udp_v4(local) {
            return Some(pid);
        }
        self.refresh_udp_v4_cache()?;
        self.lookup_udp_v4(local)
    }

    fn find_pid_udp_v6_cached(&self, local: SocketAddrV6) -> Option<u32> {
        if self.is_udp_v6_stale() {
            self.refresh_udp_v6_cache()?;
            return self.lookup_udp_v6(local);
        }
        if let Some(pid) = self.lookup_udp_v6(local) {
            return Some(pid);
        }
        self.refresh_udp_v6_cache()?;
        self.lookup_udp_v6(local)
    }

    fn is_tcp_v4_stale(&self) -> bool {
        let cache = self.session_cache.lock().unwrap();
        is_stale(cache.tcp_v4_last_refresh)
    }

    fn is_tcp_v6_stale(&self) -> bool {
        let cache = self.session_cache.lock().unwrap();
        is_stale(cache.tcp_v6_last_refresh)
    }

    fn is_udp_v4_stale(&self) -> bool {
        let cache = self.session_cache.lock().unwrap();
        is_stale(cache.udp_v4_last_refresh)
    }

    fn is_udp_v6_stale(&self) -> bool {
        let cache = self.session_cache.lock().unwrap();
        is_stale(cache.udp_v6_last_refresh)
    }

    fn lookup_tcp_v4(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<u32> {
        let key = (*local.ip(), *remote.ip(), local.port(), remote.port());
        let cache = self.session_cache.lock().unwrap();
        cache.tcp_v4.get(&key).copied()
    }

    fn lookup_tcp_v6(&self, local: SocketAddrV6, remote: SocketAddrV6) -> Option<u32> {
        let key = (*local.ip(), *remote.ip(), local.port(), remote.port());
        let cache = self.session_cache.lock().unwrap();
        cache.tcp_v6.get(&key).copied()
    }

    fn lookup_udp_v4(&self, local: SocketAddrV4) -> Option<u32> {
        let key = (*local.ip(), local.port());
        let cache = self.session_cache.lock().unwrap();
        if let Some(pid) = cache.udp_v4.get(&key) {
            return Some(*pid);
        }
        if *local.ip() != Ipv4Addr::UNSPECIFIED {
            let wildcard = (Ipv4Addr::UNSPECIFIED, local.port());
            return cache.udp_v4.get(&wildcard).copied();
        }
        None
    }

    fn lookup_udp_v6(&self, local: SocketAddrV6) -> Option<u32> {
        let key = (*local.ip(), local.port());
        let cache = self.session_cache.lock().unwrap();
        if let Some(pid) = cache.udp_v6.get(&key) {
            return Some(*pid);
        }
        if *local.ip() != Ipv6Addr::UNSPECIFIED {
            let wildcard = (Ipv6Addr::UNSPECIFIED, local.port());
            return cache.udp_v6.get(&wildcard).copied();
        }
        None
    }

    fn refresh_tcp_v4_cache(&self) -> Option<()> {
        let table = get_tcp_table(AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL).ok()?;
        let mut cache = self.session_cache.lock().unwrap();
        rebuild_tcp_v4_map(&table, &mut cache.tcp_v4);
        cache.tcp_v4_last_refresh = Some(Instant::now());
        Some(())
    }

    fn refresh_tcp_v6_cache(&self) -> Option<()> {
        let table = get_tcp_table(AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL).ok()?;
        let mut cache = self.session_cache.lock().unwrap();
        rebuild_tcp_v6_map(&table, &mut cache.tcp_v6);
        cache.tcp_v6_last_refresh = Some(Instant::now());
        Some(())
    }

    fn refresh_udp_v4_cache(&self) -> Option<()> {
        let table = get_udp_table(AF_INET.0 as u32, UDP_TABLE_OWNER_PID).ok()?;
        let mut cache = self.session_cache.lock().unwrap();
        rebuild_udp_v4_map(&table, &mut cache.udp_v4);
        cache.udp_v4_last_refresh = Some(Instant::now());
        Some(())
    }

    fn refresh_udp_v6_cache(&self) -> Option<()> {
        let table = get_udp_table(AF_INET6.0 as u32, UDP_TABLE_OWNER_PID).ok()?;
        let mut cache = self.session_cache.lock().unwrap();
        rebuild_udp_v6_map(&table, &mut cache.udp_v6);
        cache.udp_v6_last_refresh = Some(Instant::now());
        Some(())
    }
}

#[async_trait::async_trait]
impl ProcessLookup for WindowsProcessLookup {
    async fn find_process_path(
        &self,
        is_udp: bool,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<String> {
        let lookup = self.clone();
        task::spawn_blocking(move || lookup.find_process_path_sync(is_udp, src, dst))
            .await
            .context("process lookup task failed")?
    }
}

fn rebuild_tcp_v4_map(table: &[u8], map: &mut HashMap<TcpKeyV4, u32>) {
    let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();
    map.clear();
    map.reserve(entries);

    for i in 0..entries {
        let row = unsafe { &*rows.add(i) };
        let key = (
            Ipv4Addr::from(u32::from_be(row.dwLocalAddr)),
            Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)),
            u16::from_be(row.dwLocalPort as u16),
            u16::from_be(row.dwRemotePort as u16),
        );
        map.insert(key, row.dwOwningPid);
    }
}

fn is_stale(last_refresh: Option<Instant>) -> bool {
    match last_refresh {
        Some(ts) => ts.elapsed() > SESSION_CACHE_MAX_AGE,
        None => true,
    }
}

fn rebuild_tcp_v6_map(table: &[u8], map: &mut HashMap<TcpKeyV6, u32>) {
    let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();
    map.clear();
    map.reserve(entries);

    for i in 0..entries {
        let row = unsafe { &*rows.add(i) };
        let key = (
            Ipv6Addr::from(row.ucLocalAddr),
            Ipv6Addr::from(row.ucRemoteAddr),
            u16::from_be(row.dwLocalPort as u16),
            u16::from_be(row.dwRemotePort as u16),
        );
        map.insert(key, row.dwOwningPid);
    }
}

fn rebuild_udp_v4_map(table: &[u8], map: &mut HashMap<UdpKeyV4, u32>) {
    let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();
    map.clear();
    map.reserve(entries);

    for i in 0..entries {
        let row = unsafe { &*rows.add(i) };
        let key = (
            Ipv4Addr::from(u32::from_be(row.dwLocalAddr)),
            u16::from_be(row.dwLocalPort as u16),
        );
        map.insert(key, row.dwOwningPid);
    }
}

fn rebuild_udp_v6_map(table: &[u8], map: &mut HashMap<UdpKeyV6, u32>) {
    let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();
    map.clear();
    map.reserve(entries);

    for i in 0..entries {
        let row = unsafe { &*rows.add(i) };
        let key = (
            Ipv6Addr::from(row.ucLocalAddr),
            u16::from_be(row.dwLocalPort as u16),
        );
        map.insert(key, row.dwOwningPid);
    }
}

fn get_tcp_table(af: u32, class: TCP_TABLE_CLASS) -> Result<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        GetExtendedTcpTable(None, &mut size, false, af, class, 0);
    }

    if size == 0 {
        return Err(anyhow::anyhow!("GetExtendedTcpTable size returned 0"));
    }

    let mut buffer = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr().cast()),
            &mut size,
            false,
            af,
            class,
            0,
        )
    };

    if res != NO_ERROR.0 {
        return Err(anyhow::anyhow!("GetExtendedTcpTable failed: {res}"));
    }

    Ok(buffer)
}

fn get_udp_table(af: u32, class: UDP_TABLE_CLASS) -> Result<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        GetExtendedUdpTable(None, &mut size, false, af, class, 0);
    }

    if size == 0 {
        return Err(anyhow::anyhow!("GetExtendedUdpTable size returned 0"));
    }

    let mut buffer = vec![0u8; size as usize];
    let res = unsafe {
        GetExtendedUdpTable(
            Some(buffer.as_mut_ptr().cast()),
            &mut size,
            false,
            af,
            class,
            0,
        )
    };

    if res != NO_ERROR.0 {
        return Err(anyhow::anyhow!("GetExtendedUdpTable failed: {res}"));
    }

    Ok(buffer)
}

fn query_process_path(pid: u32) -> Result<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .with_context(|| format!("OpenProcess failed for pid {pid}"))?;

    let mut buffer = vec![0u16; 260];
    let mut size = buffer.len() as u32;
    let query_result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    query_result.with_context(|| format!("QueryFullProcessImageNameW failed for pid {pid}"))?;

    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    Ok(path)
}
