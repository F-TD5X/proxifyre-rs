use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Socks5Dialer {
    proxy_addr: SocketAddr,
    auth: Option<Socks5Auth>,
    prefer_ipv4_mapped_ipv6: bool,
}

#[derive(Clone, Debug)]
struct Socks5Auth {
    username: String,
    password: String,
}

impl Socks5Dialer {
    pub fn new(endpoint: &str) -> io::Result<Self> {
        let (proxy_addr, auth) = parse_socks5_endpoint(endpoint)?;
        let prefer_ipv4_mapped_ipv6 = proxy_addr.is_ipv6();
        Ok(Self {
            proxy_addr,
            auth,
            prefer_ipv4_mapped_ipv6,
        })
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    pub fn connect_tcp(&self, dst: SocketAddr) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(self.proxy_addr)?;
        stream.set_nodelay(true).ok();
        handshake(&mut stream, self.auth.as_ref())?;
        let dst = maybe_map_ipv4_to_ipv6_mapped(dst, self.prefer_ipv4_mapped_ipv6);
        send_request(&mut stream, Command::Connect, dst)?;
        Ok(stream)
    }

    pub fn udp_associate(&self) -> io::Result<Socks5UdpAssociation> {
        let mut stream = TcpStream::connect(self.proxy_addr)?;
        stream.set_nodelay(true).ok();
        handshake(&mut stream, self.auth.as_ref())?;
        // Bind address 0.0.0.0:0 to let proxy pick the relay.
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let relay = send_request(&mut stream, Command::UdpAssociate, bind_addr)?;
        let relay = normalize_udp_relay(relay, self.proxy_addr);

        let udp = match relay {
            SocketAddr::V4(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
            SocketAddr::V6(_) => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?,
        };
        udp.connect(relay)?;
        udp.set_read_timeout(Some(Duration::from_millis(500)))?;

        Ok(Socks5UdpAssociation {
            udp,
            prefer_ipv4_mapped_ipv6: self.prefer_ipv4_mapped_ipv6,
            _tcp: stream,
        })
    }
}

pub struct Socks5UdpAssociation {
    pub udp: UdpSocket,
    prefer_ipv4_mapped_ipv6: bool,
    _tcp: TcpStream,
}

impl Socks5UdpAssociation {
    pub fn send_to(&self, payload: &[u8], dst: SocketAddr) -> io::Result<usize> {
        let dst = maybe_map_ipv4_to_ipv6_mapped(dst, self.prefer_ipv4_mapped_ipv6);
        let buf = build_udp_request(dst, payload);
        self.udp.send(&buf)
    }

    pub fn recv_datagram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let n = match self.udp.recv(buf) {
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Err(err),
            Err(err) => return Err(err),
        };

        let (payload_offset, addr) = parse_udp_response(&buf[..n])?;
        let payload_len = n.saturating_sub(payload_offset);
        buf.copy_within(payload_offset..n, 0);
        Ok((payload_len, addr))
    }
}

#[derive(Copy, Clone, Debug)]
enum Command {
    Connect,
    UdpAssociate,
}

impl Command {
    fn as_byte(self) -> u8 {
        match self {
            Command::Connect => 0x01,
            Command::UdpAssociate => 0x03,
        }
    }
}

fn parse_socks5_endpoint(endpoint: &str) -> io::Result<(SocketAddr, Option<Socks5Auth>)> {
    let (scheme, rest) = if let Some(pos) = endpoint.find("://") {
        (&endpoint[..pos], &endpoint[pos + 3..])
    } else {
        ("", endpoint)
    };

    if !scheme.is_empty() && scheme != "socks5" && scheme != "socks5h" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported proxy scheme: {scheme}"),
        ));
    }

    let (auth_part, host_part) = if let Some(at) = rest.rfind('@') {
        (&rest[..at], &rest[at + 1..])
    } else {
        ("", rest)
    };

    let auth = if !auth_part.is_empty() {
        let mut split = auth_part.splitn(2, ':');
        let username = split.next().unwrap_or("");
        let password = split.next().unwrap_or("");
        if username.is_empty() || password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SOCKS5 credentials format",
            ));
        }
        Some(Socks5Auth {
            username: username.to_string(),
            password: password.to_string(),
        })
    } else {
        None
    };

    let (host, port_str) = split_host_port(host_part)?;
    let host = host.trim();
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing SOCKS5 host",
        ));
    }

    let host = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };

    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let resolved = format!("{host}:{port_str}")
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "failed to resolve SOCKS5 host"))?;
            resolved.ip()
        }
    };

    let port: u16 = port_str.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SOCKS5 endpoint port",
        )
    })?;

    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid SOCKS5 endpoint port",
        ));
    }

    Ok((SocketAddr::new(ip, port), auth))
}

fn split_host_port(input: &str) -> io::Result<(&str, &str)> {
    if input.starts_with('[') {
        let end = input.find(']').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 host format")
        })?;
        let host = &input[..=end];
        let rest = &input[end + 1..];
        if !rest.starts_with(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing port separator",
            ));
        }
        return Ok((host, &rest[1..]));
    }

    let pos = input.rfind(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port separator")
    })?;
    Ok((&input[..pos], &input[pos + 1..]))
}

fn handshake(stream: &mut TcpStream, auth: Option<&Socks5Auth>) -> io::Result<()> {
    if auth.is_some() {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00])?;
    }

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp)?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        match resp[1] {
            0x02 => {
                let auth = auth.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, "SOCKS5 auth required")
                })?;
                username_password_auth(stream, auth)?;
                return Ok(());
            }
            0xFF => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "SOCKS5 auth methods rejected",
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("SOCKS5 auth failed: {resp:?}"),
                ));
            }
        }
    }
    Ok(())
}

fn username_password_auth(stream: &mut TcpStream, auth: &Socks5Auth) -> io::Result<()> {
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 credentials too long",
        ));
    }

    let mut buf = Vec::with_capacity(username.len() + password.len() + 3);
    buf.push(0x01);
    buf.push(username.len() as u8);
    buf.extend_from_slice(username);
    buf.push(password.len() as u8);
    buf.extend_from_slice(password);
    stream.write_all(&buf)?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp)?;
    if resp[0] != 0x01 || resp[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "SOCKS5 username/password auth failed",
        ));
    }
    Ok(())
}

fn send_request(stream: &mut TcpStream, cmd: Command, dst: SocketAddr) -> io::Result<SocketAddr> {
    let mut req = Vec::with_capacity(32);
    req.push(0x05);
    req.push(cmd.as_byte());
    req.push(0x00);
    encode_addr(&mut req, dst);
    stream.write_all(&req)?;

    read_reply(stream)
}

fn read_reply(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("invalid SOCKS5 response version: {}", header[0]),
        ));
    }
    if header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SOCKS5 request failed with code: {}", header[1]),
        ));
    }

    let atyp = header[3];
    read_addr_with_atyp(stream, atyp)
}

fn read_addr_with_atyp(stream: &mut TcpStream, atyp: u8) -> io::Result<SocketAddr> {
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr)?;
            let port = read_port(stream)?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr)?;
            let port = read_port(stream)?;
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut host = vec![0u8; len[0] as usize];
            stream.read_exact(&mut host)?;
            let port = read_port(stream)?;
            let host = String::from_utf8_lossy(&host).to_string();
            let resolved = (host.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to resolve host"))?;
            Ok(resolved)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unsupported SOCKS5 address type: {atyp}"),
        )),
    }
}

fn read_port(stream: &mut TcpStream) -> io::Result<u16> {
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes)?;
    Ok(u16::from_be_bytes(port_bytes))
}

fn encode_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

fn build_udp_request(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(payload.len() + 32);
    buf.extend_from_slice(&[0x00, 0x00, 0x00]);
    encode_addr(&mut buf, dst);
    buf.extend_from_slice(payload);
    buf
}

fn parse_udp_response(buf: &[u8]) -> io::Result<(usize, SocketAddr)> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP header too short",
        ));
    }
    if buf[0] != 0x00 || buf[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP reserved bytes not zero",
        ));
    }
    if buf[2] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP fragmentation not supported",
        ));
    }

    let atyp = buf[3];
    let mut offset = 4;
    let addr = match atyp {
        0x01 => {
            if buf.len() < offset + 4 + 2 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "IPv4 addr truncated"));
            }
            let ip = Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
            offset += 4;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            SocketAddr::new(IpAddr::V4(ip), port)
        }
        0x04 => {
            if buf.len() < offset + 16 + 2 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "IPv6 addr truncated"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[offset..offset + 16]);
            offset += 16;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
        0x03 => {
            if buf.len() < offset + 1 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "domain truncated"));
            }
            let len = buf[offset] as usize;
            offset += 1;
            if buf.len() < offset + len + 2 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "domain addr truncated"));
            }
            let host = String::from_utf8_lossy(&buf[offset..offset + len]).to_string();
            offset += len;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            let resolved = (host.as_str(), port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to resolve domain"))?;
            resolved
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported UDP address type: {atyp}"),
            ))
        }
    };

    Ok((offset, addr))
}

fn maybe_map_ipv4_to_ipv6_mapped(addr: SocketAddr, prefer_mapped: bool) -> SocketAddr {
    if !prefer_mapped {
        return addr;
    }

    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        SocketAddr::V6(v6) => SocketAddr::V6(v6),
    }
}

fn normalize_udp_relay(relay: SocketAddr, proxy_addr: SocketAddr) -> SocketAddr {
    match relay {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            match proxy_addr.ip() {
                IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), v4.port()),
                IpAddr::V6(ip) => ip
                    .to_ipv4()
                    .map(|v4_ip| SocketAddr::new(IpAddr::V4(v4_ip), v4.port()))
                    .unwrap_or(relay),
            }
        }
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            match proxy_addr.ip() {
                IpAddr::V6(ip) => SocketAddr::new(IpAddr::V6(ip), v6.port()),
                IpAddr::V4(ip) => {
                    SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), v6.port())
                }
            }
        }
        _ => relay,
    }
}
