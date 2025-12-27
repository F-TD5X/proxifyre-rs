use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_CLASS, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_CLASS, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Clone, Default)]
pub struct ProcessLookup {
    cache: Arc<Mutex<HashMap<u32, CachedProcess>>>,
}

const PROCESS_CACHE_TTL: Duration = Duration::from_secs(300);
const PROCESS_CACHE_MAX: usize = 1024;

#[derive(Clone)]
struct CachedProcess {
    path: String,
    last_seen: Instant,
}

impl ProcessLookup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn find_process_path(&self, is_udp: bool, src: SocketAddr, dst: SocketAddr) -> Result<String> {
        let pid = if is_udp {
            match (src, dst) {
                (SocketAddr::V4(local), _) => find_pid_udp_v4(local),
                (SocketAddr::V6(local), _) => find_pid_udp_v6(local),
            }
        } else {
            match (src, dst) {
                (SocketAddr::V4(local), SocketAddr::V4(remote)) => find_pid_tcp_v4(local, remote),
                (SocketAddr::V6(local), SocketAddr::V6(remote)) => find_pid_tcp_v6(local, remote),
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
}

fn find_pid_tcp_v4(local: SocketAddrV4, remote: SocketAddrV4) -> Option<u32> {
    let table = get_tcp_table(AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL).ok()?;
    let table = unsafe { &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();

    for i in 0..entries {
        let row = unsafe { *rows.add(i) };
        let row_local_port = u16::from_be(row.dwLocalPort as u16);
        let row_remote_port = u16::from_be(row.dwRemotePort as u16);
        let row_local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        let row_remote_addr = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));

        if row_local_port == local.port()
            && row_remote_port == remote.port()
            && row_local_addr == *local.ip()
            && row_remote_addr == *remote.ip()
        {
            return Some(row.dwOwningPid);
        }
    }

    None
}

fn find_pid_tcp_v6(local: SocketAddrV6, remote: SocketAddrV6) -> Option<u32> {
    let table = get_tcp_table(AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL).ok()?;
    let table = unsafe { &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();

    for i in 0..entries {
        let row = unsafe { *rows.add(i) };
        let row_local_port = u16::from_be(row.dwLocalPort as u16);
        let row_remote_port = u16::from_be(row.dwRemotePort as u16);
        let row_local_addr = Ipv6Addr::from(row.ucLocalAddr);
        let row_remote_addr = Ipv6Addr::from(row.ucRemoteAddr);

        if row_local_port == local.port()
            && row_remote_port == remote.port()
            && row_local_addr == *local.ip()
            && row_remote_addr == *remote.ip()
        {
            return Some(row.dwOwningPid);
        }
    }

    None
}

fn find_pid_udp_v4(local: SocketAddrV4) -> Option<u32> {
    let table = get_udp_table(AF_INET.0 as u32, UDP_TABLE_OWNER_PID).ok()?;
    let table = unsafe { &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();

    for i in 0..entries {
        let row = unsafe { *rows.add(i) };
        let row_local_port = u16::from_be(row.dwLocalPort as u16);
        let row_local_addr = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));

        if row_local_port == local.port()
            && (row_local_addr == *local.ip() || row_local_addr == Ipv4Addr::UNSPECIFIED)
        {
            return Some(row.dwOwningPid);
        }
    }

    None
}

fn find_pid_udp_v6(local: SocketAddrV6) -> Option<u32> {
    let table = get_udp_table(AF_INET6.0 as u32, UDP_TABLE_OWNER_PID).ok()?;
    let table = unsafe { &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let entries = table.dwNumEntries as usize;
    let rows = table.table.as_ptr();

    for i in 0..entries {
        let row = unsafe { *rows.add(i) };
        let row_local_port = u16::from_be(row.dwLocalPort as u16);
        let row_local_addr = Ipv6Addr::from(row.ucLocalAddr);

        if row_local_port == local.port()
            && (row_local_addr == *local.ip() || row_local_addr == Ipv6Addr::UNSPECIFIED)
        {
            return Some(row.dwOwningPid);
        }
    }

    None
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
