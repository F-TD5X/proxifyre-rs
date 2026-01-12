use super::SocksLocalRouter;
use super::packet::ProxyDirection;
use anyhow::{Result, anyhow};
use log::error;
use ndisapi::{
    AsyncNdisapiAdapter, DirectionFlags, FilterFlags, IntermediateBuffer, IphlpNetworkAdapterInfo,
    MacAddress, Ndisapi,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;
use windows::Win32::Foundation::{HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::GetBestInterface;

const PACKET_NUMBER: usize = 510;

pub(super) async fn run_packet_loop(
    driver_name: &str,
    adapter_name: Arc<Mutex<String>>,
    shutdown: Arc<AtomicBool>,
    restart: Arc<AtomicBool>,
    router: Arc<SocksLocalRouter>,
) -> Result<()> {
    loop {
        let adapter_name = adapter_name.lock().unwrap().clone();
        #[allow(clippy::arc_with_non_send_sync)]
        let driver = Arc::new(Ndisapi::new(driver_name)?);
        let adapter_handle = match find_adapter_handle(driver.as_ref(), &adapter_name) {
            Ok(handle) => handle,
            Err(err) => {
                error!("adapter not found ({adapter_name}): {err}");
                if shutdown.load(Ordering::Relaxed) {
                    return Ok(());
                }
                time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        let mut adapter = AsyncNdisapiAdapter::new(Arc::clone(&driver), adapter_handle)?;
        adapter.set_adapter_mode(FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)?;

        let mut packets = vec![IntermediateBuffer::default(); PACKET_NUMBER];
        let mut cleanup_counter = 0u32;

        while !shutdown.load(Ordering::Relaxed) {
            if restart.swap(false, Ordering::Relaxed) {
                break;
            }

            let packets_read = match adapter.read_packets::<PACKET_NUMBER>(&mut packets).await {
                Ok(packets_read) => packets_read,
                Err(_) => {
                    continue;
                }
            };

            if packets_read == 0 {
                continue;
            }

            let mut send_to_adapter = Vec::with_capacity(packets_read);
            let mut send_to_mstcp = Vec::with_capacity(packets_read);
            let mut routing = Vec::with_capacity(packets_read);

            for packet in packets[..packets_read].iter_mut() {
                let proxy_direction = router.process_packet(packet).await;
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

                routing.push(send_to_adapter);
            }

            for (packet, to_adapter) in packets[..packets_read].iter().zip(routing.into_iter()) {
                if to_adapter {
                    send_to_adapter.push(packet);
                } else {
                    send_to_mstcp.push(packet);
                }
            }

            if !send_to_adapter.is_empty() {
                let _ = adapter.send_packets_to_adapter::<PACKET_NUMBER>(send_to_adapter);
            }

            if !send_to_mstcp.is_empty() {
                let _ = adapter.send_packets_to_mstcp::<PACKET_NUMBER>(send_to_mstcp);
            }

            cleanup_counter += 1;
            if cleanup_counter >= 20 {
                cleanup_counter = 0;
                router.cleanup_stale_udp_endpoints();
            }
        }

        adapter.set_adapter_mode(FilterFlags::default()).ok();

        if shutdown.load(Ordering::Relaxed) {
            break;
        }
    }

    Ok(())
}

pub(super) fn select_best_adapter_name(driver: &Ndisapi) -> Result<String> {
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
