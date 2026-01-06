use crate::proxy::socks5::{Socks5Dialer, Socks5UdpAssociation};
use log::{error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time;

pub type QueryTcpRemotePeer =
    Arc<dyn Fn(SocketAddr, SocketAddr) -> io::Result<(IpAddr, u16)> + Send + Sync>;
pub type QueryUdpRemotePeer =
    Arc<dyn Fn(SocketAddr, SocketAddr) -> io::Result<(IpAddr, u16)> + Send + Sync>;

const UDP_QUEUE_SIZE: usize = 1024;
const UDP_ASSOCIATION_TIMEOUT_SECS: u64 = 120;

pub struct TransparentProxy {
    port: u16,
    socks5: Socks5Dialer,
    tcp_port_v4: AtomicU16,
    tcp_port_v6: AtomicU16,
    udp_port_v4: AtomicU16,
    udp_port_v6: AtomicU16,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    query_tcp_remote_peer: QueryTcpRemotePeer,
    query_udp_remote_peer: QueryUdpRemotePeer,
    udp_connections: Arc<Mutex<HashMap<String, UdpAssociationEntry>>>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    udp_reader_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl TransparentProxy {
    pub fn new(
        local_proxy_port: u16,
        socks5: Socks5Dialer,
        query_tcp_remote_peer: QueryTcpRemotePeer,
        query_udp_remote_peer: QueryUdpRemotePeer,
    ) -> Self {
        Self {
            port: local_proxy_port,
            socks5,
            tcp_port_v4: AtomicU16::new(0),
            tcp_port_v6: AtomicU16::new(0),
            udp_port_v4: AtomicU16::new(0),
            udp_port_v6: AtomicU16::new(0),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            query_tcp_remote_peer,
            query_udp_remote_peer,
            udp_connections: Arc::new(Mutex::new(HashMap::new())),
            handles: Mutex::new(Vec::new()),
            udp_reader_handles: Mutex::new(Vec::new()),
        }
    }

    pub fn get_local_tcp_proxy_port_v4(&self) -> u16 {
        self.tcp_port_v4.load(Ordering::Relaxed)
    }

    pub fn get_local_tcp_proxy_port_v6(&self) -> u16 {
        self.tcp_port_v6.load(Ordering::Relaxed)
    }

    pub fn get_local_udp_proxy_port_v4(&self) -> u16 {
        self.udp_port_v4.load(Ordering::Relaxed)
    }

    pub fn get_local_udp_proxy_port_v6(&self) -> u16 {
        self.udp_port_v6.load(Ordering::Relaxed)
    }

    pub async fn start(self: &Arc<Self>) -> io::Result<()> {
        let tcp_listener = bind_dual_stack_tcp(self.port)?;
        let tcp_port = tcp_listener.local_addr()?.port();
        self.tcp_port_v4.store(tcp_port, Ordering::Relaxed);
        self.tcp_port_v6.store(tcp_port, Ordering::Relaxed);

        let udp_listener = bind_dual_stack_udp(self.port)?;
        let udp_port = udp_listener.local_addr()?.port();
        self.udp_port_v4.store(udp_port, Ordering::Relaxed);
        self.udp_port_v6.store(udp_port, Ordering::Relaxed);

        info!(
            "Transparent proxy listening on TCP {} and UDP {} (dual-stack)",
            tcp_listener.local_addr()?,
            udp_listener.local_addr()?
        );

        let tcp_proxy = Arc::clone(self);
        let tcp_handle = tokio::spawn(async move {
            tcp_proxy.accept_tcp_connections(tcp_listener).await;
        });
        self.handles.lock().await.push(tcp_handle);

        let udp_listener = Arc::new(udp_listener);
        let (udp_tx, udp_rx) = mpsc::channel(UDP_QUEUE_SIZE);

        let udp_proxy = Arc::clone(self);
        let udp_listener_worker = Arc::clone(&udp_listener);
        let udp_worker = tokio::spawn(async move {
            udp_proxy.udp_worker_loop(udp_listener_worker, udp_rx).await;
        });
        self.handles.lock().await.push(udp_worker);

        let udp_proxy = Arc::clone(self);
        let udp_listener_accept = Arc::clone(&udp_listener);
        let udp_handle = tokio::spawn(async move {
            udp_proxy
                .accept_udp_connections(udp_listener_accept, udp_tx)
                .await;
        });
        self.handles.lock().await.push(udp_handle);

        Ok(())
    }

    pub async fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();

        let mut handles = self.handles.lock().await;
        while let Some(handle) = handles.pop() {
            let _ = handle.await;
        }

        let mut udp_reader_handles = self.udp_reader_handles.lock().await;
        while let Some(handle) = udp_reader_handles.pop() {
            let _ = handle.await;
        }
    }

    async fn accept_tcp_connections(self: Arc<Self>, listener: TcpListener) {
        loop {
            tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    break;
                }
                res = listener.accept() => {
                    match res {
                        Ok((conn, _)) => {
                            let proxy = Arc::clone(&self);
                            tokio::spawn(async move {
                                proxy.handle_tcp_connection(conn).await;
                            });
                        }
                        Err(err) => {
                            error!("failed to accept TCP connection: {err}");
                            time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }

    async fn handle_tcp_connection(self: Arc<Self>, mut conn: TcpStream) {
        let peer = match conn.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                error!("failed to get TCP peer addr: {err}");
                return;
            }
        };
        let local = match conn.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                error!("failed to get TCP local addr: {err}");
                return;
            }
        };

        let (dst_ip, dst_port) = match (self.query_tcp_remote_peer)(peer, local) {
            Ok(value) => value,
            Err(err) => {
                error!("failed to get destination address: {err}");
                return;
            }
        };

        let dst_addr = SocketAddr::new(dst_ip, dst_port);
        let mut remote = match self.socks5.connect_tcp(dst_addr).await {
            Ok(stream) => stream,
            Err(err) => {
                error!("[TCP] Connection failed: {} -> {} ({err})", peer, dst_addr);
                return;
            }
        };

        let _ = copy_bidirectional(&mut conn, &mut remote).await;
    }

    async fn accept_udp_connections(
        self: Arc<Self>,
        listener: Arc<UdpSocket>,
        tx: mpsc::Sender<UdpPacket>,
    ) {
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    break;
                }
                res = listener.recv_from(&mut buf) => {
                    match res {
                        Ok((n, client_addr)) => {
                            let packet = buf[..n].to_vec();
                            if let Err(err) = tx.try_send(UdpPacket { packet, client_addr }) {
                                match err {
                                    mpsc::error::TrySendError::Full(_) => {
                                        warn!("dropping UDP packet (queue full)");
                                    }
                                    mpsc::error::TrySendError::Closed(_) => break,
                                }
                            }
                        }
                        Err(err) => {
                            error!("failed to read UDP packet: {err}");
                            time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }

    async fn udp_worker_loop(
        self: Arc<Self>,
        listener: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<UdpPacket>,
    ) {
        let mut cleanup = time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    break;
                }
                _ = cleanup.tick() => {
                    self.cleanup_stale_udp_associations().await;
                }
                work = rx.recv() => {
                    match work {
                        Some(work) => {
                            let this = Arc::clone(&self);
                            this.handle_udp_packet(Arc::clone(&listener), work.packet, work.client_addr).await;
                        }
                        None => break,
                    }
                }
            }
        }
    }

    async fn handle_udp_packet(
        self: Arc<Self>,
        listener: Arc<UdpSocket>,
        packet: Vec<u8>,
        client_addr: SocketAddr,
    ) {
        let local_addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                error!("failed to get UDP local addr: {err}");
                return;
            }
        };

        let (dst_ip, dst_port) = match (self.query_udp_remote_peer)(client_addr, local_addr) {
            Ok(value) => value,
            Err(err) => {
                error!("failed to get UDP destination address: {err}");
                return;
            }
        };

        let local_key = SocketAddr::new(dst_ip, client_addr.port()).to_string();
        let remote_addr = SocketAddr::new(dst_ip, dst_port);

        let mut assoc = None;
        {
            let mut map = self.udp_connections.lock().await;
            if let Some(entry) = map.get_mut(&local_key) {
                entry.last_active = Instant::now();
                assoc = Some(Arc::clone(&entry.assoc));
            }
        }

        let assoc = match assoc {
            Some(existing) => existing,
            None => {
                let assoc = match self.socks5.udp_associate().await {
                    Ok(assoc) => Arc::new(assoc),
                    Err(err) => {
                        error!(
                            "[UDP] Session failed: {} -> {} ({err})",
                            client_addr, remote_addr
                        );
                        return;
                    }
                };

                let mut map = self.udp_connections.lock().await;
                if let Some(entry) = map.get_mut(&local_key) {
                    entry.last_active = Instant::now();
                    Arc::clone(&entry.assoc)
                } else {
                    self.spawn_udp_reader(
                        Arc::clone(&assoc),
                        Arc::clone(&listener),
                        local_key.clone(),
                        client_addr,
                        remote_addr,
                    )
                    .await;

                    map.insert(
                        local_key.clone(),
                        UdpAssociationEntry {
                            assoc: Arc::clone(&assoc),
                            last_active: Instant::now(),
                        },
                    );
                    assoc
                }
            }
        };

        if let Err(err) = assoc.send_to(&packet, remote_addr).await {
            error!("failed to send UDP packet to remote host: {err}");
        }
    }

    async fn spawn_udp_reader(
        &self,
        assoc: Arc<Socks5UdpAssociation>,
        listener: Arc<UdpSocket>,
        local_key: String,
        client_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) {
        let shutdown = Arc::clone(&self.shutdown);
        let shutdown_notify = Arc::clone(&self.shutdown_notify);
        let connections = Arc::clone(&self.udp_connections);
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while !shutdown.load(Ordering::Relaxed) {
                let result = tokio::select! {
                    _ = shutdown_notify.notified() => {
                        break;
                    }
                    res = time::timeout(Duration::from_millis(500), assoc.recv_datagram(&mut buf)) => {
                        res
                    }
                };

                match result {
                    Ok(Ok((payload_len, _addr))) => {
                        if payload_len == 0 {
                            continue;
                        }
                        if let Err(err) = listener.send_to(&buf[..payload_len], client_addr).await {
                            error!("failed to send UDP response to client: {err}");
                        }
                        let mut map = connections.lock().await;
                        if let Some(entry) = map.get_mut(&local_key) {
                            entry.last_active = Instant::now();
                        } else {
                            break;
                        }
                    }
                    Ok(Err(err)) => {
                        error!(
                            "[UDP] Session destroyed: {} -> {} ({err})",
                            client_addr, remote_addr
                        );
                        break;
                    }
                    Err(_) => {
                        if connections.lock().await.get(&local_key).is_none() {
                            break;
                        }
                    }
                }
            }

            let mut map = connections.lock().await;
            map.remove(&local_key);
        });
        self.udp_reader_handles.lock().await.push(handle);
    }

    async fn cleanup_stale_udp_associations(&self) {
        let timeout = Duration::from_secs(UDP_ASSOCIATION_TIMEOUT_SECS);
        let now = Instant::now();
        let mut map = self.udp_connections.lock().await;
        map.retain(|_, entry| now.duration_since(entry.last_active) < timeout);
    }
}

struct UdpAssociationEntry {
    assoc: Arc<Socks5UdpAssociation>,
    last_active: Instant,
}

struct UdpPacket {
    packet: Vec<u8>,
    client_addr: SocketAddr,
}

fn bind_dual_stack_tcp(port: u16) -> io::Result<TcpListener> {
    let socket = bind_dual_stack_socket(port, Type::STREAM, Protocol::TCP, true)?;
    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

fn bind_dual_stack_udp(port: u16) -> io::Result<UdpSocket> {
    let socket = bind_dual_stack_socket(port, Type::DGRAM, Protocol::UDP, false)?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

fn bind_dual_stack_socket(
    port: u16,
    socket_type: Type,
    protocol: Protocol,
    listen: bool,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, socket_type, Some(protocol))?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    let addr =
        socket2::SockAddr::from(std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)));
    socket.bind(&addr)?;
    if listen {
        socket.listen(128)?;
    }
    Ok(socket)
}
