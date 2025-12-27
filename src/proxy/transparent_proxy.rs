use crate::proxy::socks5::{Socks5Dialer, Socks5UdpAssociation};
use std::collections::HashMap;
use std::io;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub type QueryTcpRemotePeer = Arc<dyn Fn(SocketAddr) -> io::Result<(IpAddr, u16)> + Send + Sync>;
pub type QueryUdpRemotePeer = Arc<dyn Fn(SocketAddr) -> io::Result<(IpAddr, u16)> + Send + Sync>;

pub struct TransparentProxy {
    port: u16,
    socks5: Socks5Dialer,
    tcp_port_v4: AtomicU16,
    tcp_port_v6: AtomicU16,
    udp_port_v4: AtomicU16,
    udp_port_v6: AtomicU16,
    shutdown: Arc<AtomicBool>,
    query_tcp_remote_peer: QueryTcpRemotePeer,
    query_udp_remote_peer: QueryUdpRemotePeer,
    udp_connections: Arc<Mutex<HashMap<String, Arc<Socks5UdpAssociation>>>>,
    handles: Mutex<Vec<JoinHandle<()>>>,
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
            query_tcp_remote_peer,
            query_udp_remote_peer,
            udp_connections: Arc::new(Mutex::new(HashMap::new())),
            handles: Mutex::new(Vec::new()),
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

    pub fn start(self: &Arc<Self>) -> io::Result<()> {
        let tcp_listener = bind_dual_stack_tcp(self.port)?;
        let tcp_port = tcp_listener.local_addr()?.port();
        self.tcp_port_v4.store(tcp_port, Ordering::Relaxed);
        self.tcp_port_v6.store(tcp_port, Ordering::Relaxed);

        let udp_listener = bind_dual_stack_udp(self.port)?;
        let udp_port = udp_listener.local_addr()?.port();
        self.udp_port_v4.store(udp_port, Ordering::Relaxed);
        self.udp_port_v6.store(udp_port, Ordering::Relaxed);

        println!(
            "Transparent proxy listening on TCP {} and UDP {} (dual-stack)",
            tcp_listener.local_addr()?,
            udp_listener.local_addr()?
        );

        let tcp_proxy = Arc::clone(self);
        let tcp_handle = thread::spawn(move || tcp_proxy.accept_tcp_connections(tcp_listener));
        self.handles.lock().unwrap().push(tcp_handle);

        let udp_proxy = Arc::clone(self);
        let udp_handle = thread::spawn(move || udp_proxy.accept_udp_connections(udp_listener));
        self.handles.lock().unwrap().push(udp_handle);

        Ok(())
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let mut handles = self.handles.lock().unwrap();
        while let Some(handle) = handles.pop() {
            let _ = handle.join();
        }
    }

    fn accept_tcp_connections(self: Arc<Self>, listener: TcpListener) {
        while !self.shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((conn, _)) => {
                    let _ = conn.set_nonblocking(false);
                    let proxy = Arc::clone(&self);
                    thread::spawn(move || proxy.handle_tcp_connection(conn));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    eprintln!("failed to accept TCP connection: {err}");
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    fn handle_tcp_connection(self: Arc<Self>, mut conn: TcpStream) {
        let peer = match conn.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                eprintln!("failed to get TCP peer addr: {err}");
                return;
            }
        };

        let (dst_ip, dst_port) = match (self.query_tcp_remote_peer)(peer) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("failed to get destination address: {err}");
                return;
            }
        };

        let dst_addr = SocketAddr::new(dst_ip, dst_port);
        let mut remote = match self.socks5.connect_tcp(dst_addr) {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("[TCP] Connection failed: {} -> {} ({err})", peer, dst_addr);
                return;
            }
        };

        let mut remote_clone = match remote.try_clone() {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("failed to clone remote stream: {err}");
                return;
            }
        };
        let mut conn_clone = match conn.try_clone() {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("failed to clone local stream: {err}");
                return;
            }
        };

        let uplink = thread::spawn(move || {
            let _ = io::copy(&mut conn_clone, &mut remote_clone);
        });

        let _ = io::copy(&mut remote, &mut conn);
        let _ = uplink.join();
    }

    fn accept_udp_connections(self: Arc<Self>, listener: UdpSocket) {
        let listener = Arc::new(listener);
        let mut buf = vec![0u8; 65535];

        while !self.shutdown.load(Ordering::Relaxed) {
            match listener.recv_from(&mut buf) {
                Ok((n, client_addr)) => {
                    let proxy = Arc::clone(&self);
                    let listener = Arc::clone(&listener);
                    let packet = buf[..n].to_vec();
                    thread::spawn(move || proxy.handle_udp_packet(listener, packet, client_addr));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    eprintln!("failed to read UDP packet: {err}");
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    fn handle_udp_packet(self: Arc<Self>, listener: Arc<UdpSocket>, packet: Vec<u8>, client_addr: SocketAddr) {
        let (dst_ip, dst_port) = match (self.query_udp_remote_peer)(client_addr) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("failed to get UDP destination address: {err}");
                return;
            }
        };

        let local_key = SocketAddr::new(dst_ip, client_addr.port()).to_string();
        let remote_addr = SocketAddr::new(dst_ip, dst_port);

        let assoc = {
            let mut map = self.udp_connections.lock().unwrap();
            if let Some(assoc) = map.get(&local_key) {
                Arc::clone(assoc)
            } else {
                let assoc = match self.socks5.udp_associate() {
                    Ok(assoc) => Arc::new(assoc),
                    Err(err) => {
                        eprintln!("[UDP] Session failed: {} -> {} ({err})", client_addr, remote_addr);
                        return;
                    }
                };

                self.spawn_udp_reader(
                    Arc::clone(&assoc),
                    Arc::clone(&listener),
                    Arc::clone(&self.shutdown),
                    Arc::clone(&self.udp_connections),
                    local_key.clone(),
                    client_addr,
                    remote_addr,
                );

                map.insert(local_key.clone(), Arc::clone(&assoc));
                assoc
            }
        };

        if let Err(err) = assoc.send_to(&packet, remote_addr) {
            eprintln!("failed to send UDP packet to remote host: {err}");
        }
    }

    fn spawn_udp_reader(
        &self,
        assoc: Arc<Socks5UdpAssociation>,
        listener: Arc<UdpSocket>,
        shutdown: Arc<AtomicBool>,
        connections: Arc<Mutex<HashMap<String, Arc<Socks5UdpAssociation>>>>,
        local_key: String,
        client_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) {
        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while !shutdown.load(Ordering::Relaxed) {
                match assoc.recv_datagram(&mut buf) {
                    Ok((payload_len, _addr)) => {
                        if payload_len == 0 {
                            continue;
                        }
                        if let Err(err) = listener.send_to(&buf[..payload_len], client_addr) {
                            eprintln!("failed to send UDP response to client: {err}");
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut => {
                        continue;
                    }
                    Err(err) => {
                        eprintln!("[UDP] Session destroyed: {} -> {} ({err})", client_addr, remote_addr);
                        break;
                    }
                }
            }

            let mut map = connections.lock().unwrap();
            map.remove(&local_key);
        });
    }
}

fn bind_dual_stack_tcp(port: u16) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    let addr = socket2::SockAddr::from(std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)));
    socket.bind(&addr)?;
    socket.listen(128)?;
    Ok(socket.into())
}

fn bind_dual_stack_udp(port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    let addr = socket2::SockAddr::from(std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)));
    socket.bind(&addr)?;
    Ok(socket.into())
}
