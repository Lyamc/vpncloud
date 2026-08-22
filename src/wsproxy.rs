// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use super::{
    net::{get_ip, mapped_addr, parse_listen, send_addr, Socket},
    poll::{WaitImpl, WaitResult},
    port_forwarding::PortForwarding,
    util::MsgBuffer
};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Cursor, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Arc, Mutex},
    thread::spawn,
    time::Duration
};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

use tungstenite::{
    accept, connect,
    protocol::WebSocket,
    stream::{MaybeTlsStream, NoDelay},
    Message
};
use url::Url;

macro_rules! io_error {
    ($val:expr, $format:expr) => ( {
        $val.map_err(|err| io::Error::new(io::ErrorKind::Other, format!($format, err)))
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        $val.map_err(|err| io::Error::new(io::ErrorKind::Other, format!($format, $( $arg ),+, err)))
    } );
}

fn write_addr<W: Write>(addr: SocketAddr, mut out: W) -> Result<(), io::Error> {
    let addr = mapped_addr(addr);
    match mapped_addr(addr) {
        SocketAddr::V6(addr) => {
            out.write_all(&addr.ip().octets())?;
            out.write_u16::<NetworkEndian>(addr.port())?;
        }
        _ => unreachable!()
    }
    Ok(())
}

fn read_addr<R: Read>(mut r: R) -> Result<SocketAddr, io::Error> {
    let mut ip = [0u8; 16];
    r.read_exact(&mut ip)?;
    let port = r.read_u16::<NetworkEndian>()?;
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0));
    Ok(addr)
}

fn serve_proxy_connection(stream: TcpStream) -> Result<(), io::Error> {
    let peer = stream.peer_addr()?;
    info!("WS client {} connected", peer);
    stream.set_nodelay(true)?;
    let mut websocket = io_error!(accept(stream), "Failed to initialize websocket with {}: {}", peer)?;
    let udpsocket = UdpSocket::bind("[::]:0")?;
    let mut msg = Vec::with_capacity(18);
    let mut addr = udpsocket.local_addr()?;
    info!("Listening on {} for peer {}", addr, peer);
    addr.set_ip(get_ip());
    write_addr(addr, &mut msg)?;
    io_error!(websocket.send(Message::binary(msg)), "Failed to write to ws connection: {}")?;

    let poll = WaitImpl::new(websocket.get_ref(), &udpsocket, 60 * 1000)?;
    let mut buffer = [0; 65535];
    for evt in poll {
        match evt {
            WaitResult::Socket => {
                let msg = io_error!(websocket.read(), "Failed to read message on websocket {}: {}", peer)?;
                match msg {
                    Message::Binary(data) => {
                        let dst = read_addr(Cursor::new(&data))?;
                        udpsocket.send_to(&data[18..], dst)?;
                    }
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
            WaitResult::Device => {
                let (size, addr) = udpsocket.recv_from(&mut buffer)?;
                let mut data = Vec::with_capacity(18 + size);
                write_addr(addr, &mut data)?;
                data.write_all(&buffer[..size])?;
                io_error!(websocket.send(Message::binary(data)), "Failed to write to {}: {}", peer)?;
            }
            WaitResult::Timeout => {
                io_error!(websocket.send(Message::Ping(Vec::<u8>::new().into())), "Failed to send ping: {}")?;
            }
            WaitResult::Error(err) => return Err(err)
        }
    }
    Ok(())
}

pub fn run_proxy(listen: &str) -> Result<(), io::Error> {
    let addr = parse_listen(listen, 8080);
    let server = TcpListener::bind(addr)?;
    info!("Listening on ws://{}", server.local_addr()?);
    for stream in server.incoming() {
        let stream = stream?;
        let peer = stream.peer_addr()?;
        spawn(move || {
            if let Err(err) = serve_proxy_connection(stream) {
                error!("Error on connection {}: {}", peer, err);
            }
        });
    }
    Ok(())
}

pub struct ProxyConnection {
    addr: SocketAddr,
    socket: WebSocket<MaybeTlsStream<TcpStream>>
}

impl ProxyConnection {
    fn read_message(&mut self) -> Result<Vec<u8>, io::Error> {
        loop {
            if let Message::Binary(data) = io_error!(self.socket.read(), "Failed to read from ws proxy: {}")? {
                return Ok(data.to_vec());
            }
        }
    }
}

#[cfg(unix)]
impl AsRawFd for ProxyConnection {
    fn as_raw_fd(&self) -> RawFd {
        match self.socket.get_ref() {
            MaybeTlsStream::Plain(stream) => stream.as_raw_fd(),
            _ => unimplemented!()
        }
    }
}

#[cfg(windows)]
impl AsRawSocket for ProxyConnection {
    fn as_raw_socket(&self) -> RawSocket {
        match self.socket.get_ref() {
            MaybeTlsStream::Plain(stream) => stream.as_raw_socket(),
            _ => unimplemented!()
        }
    }
}

#[cfg(windows)]
impl crate::poll::Pollable for ProxyConnection {
    fn wait_socket(&self) -> Option<std::os::windows::io::RawSocket> {
        Some(self.as_raw_socket())
    }
}

impl Socket for ProxyConnection {
    fn listen(url: &str) -> Result<Self, io::Error> {
        io_error!(Url::parse(url), "Invalid URL {}: {}", url)?;
        let (mut socket, _) = io_error!(connect(url), "Failed to connect to URL {}: {}", url)?;
        socket.get_mut().set_nodelay(true)?;
        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut con = ProxyConnection { addr, socket };
        let addr_data = con.read_message()?;
        con.addr = read_addr(Cursor::new(&addr_data))?;
        Ok(con)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        let data = self.read_message()?;
        let addr = read_addr(Cursor::new(&data))?;
        buffer.clone_from(&data[18..]);
        Ok(addr)
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        let mut msg = Vec::with_capacity(data.len() + 18);
        write_addr(addr, &mut msg)?;
        msg.write_all(data)?;
        io_error!(self.socket.send(Message::binary(msg)), "Failed to write to ws proxy: {}")?;
        Ok(data.len())
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.addr)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        None
    }
}

/// Bind address for native websocket listen, or `None` if this is a proxy-client URL.
///
/// `ws://0.0.0.0:8080`, `ws://[::]:8080`, `ws://*:8080`, and any `ws-listen://...`
/// bind a local websocket server (#205). `ws://hostname:port` still connects to a
/// remote websocket proxy (existing behaviour).
pub fn native_ws_bind(listen: &str) -> Option<String> {
    let (rest, force) = if let Some(rest) = listen.strip_prefix("ws-listen://") {
        (rest, true)
    } else if let Some(rest) = listen.strip_prefix("ws://") {
        (rest, false)
    } else {
        return None;
    };
    let hostport = rest.split('/').next().unwrap_or(rest);
    if force {
        return Some(hostport.to_string());
    }
    let host = if let Some(inner) = hostport.strip_prefix('[') {
        inner.split(']').next().unwrap_or("")
    } else if let Some((h, _)) = hostport.rsplit_once(':') {
        h
    } else {
        hostport
    };
    if host.is_empty() || host == "*" || host == "0.0.0.0" || host == "::" {
        Some(hostport.to_string())
    } else {
        None
    }
}

fn ws_peer_url(addr: SocketAddr) -> String {
    format!("ws://{}/", send_addr(addr))
}

fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        let _ = sock.set_only_v6(false);
    }
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    Ok(sock.into())
}

fn wakeup_pair() -> io::Result<(UdpSocket, SocketAddr)> {
    if let Ok(sock) = UdpSocket::bind("127.0.0.1:0") {
        sock.set_nonblocking(true)?;
        let addr = sock.local_addr()?;
        return Ok((sock, addr));
    }
    let sock = UdpSocket::bind("[::1]:0")?;
    sock.set_nonblocking(true)?;
    let addr = sock.local_addr()?;
    Ok((sock, addr))
}

fn run_ws_conn<S: Read + Write>(
    mut ws: WebSocket<S>, peer: SocketAddr, inbound: Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>,
    wakeup: UdpSocket, wakeup_addr: SocketAddr, write_rx: mpsc::Receiver<Vec<u8>>,
    conns: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>
) {
    loop {
        match ws.read() {
            Ok(Message::Binary(data)) => {
                inbound.lock().unwrap().push_back((mapped_addr(peer), data.to_vec()));
                let _ = wakeup.send_to(&[1], wakeup_addr);
            }
            Ok(Message::Ping(p)) => {
                if ws.send(Message::Pong(p)).is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => break
        }
        loop {
            match write_rx.try_recv() {
                Ok(data) => {
                    if ws.send(Message::binary(data)).is_err() {
                        conns.lock().unwrap().remove(&mapped_addr(peer));
                        return;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    conns.lock().unwrap().remove(&mapped_addr(peer));
                    return;
                }
            }
        }
    }
    conns.lock().unwrap().remove(&mapped_addr(peer));
}

/// Direct websocket transport: this node listens on TCP/WS and peers connect with `ws://`.
pub struct WsNativeSocket {
    addr: SocketAddr,
    wakeup: UdpSocket,
    wakeup_addr: SocketAddr,
    inbound: Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>,
    conns: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    connecting: Arc<Mutex<HashSet<SocketAddr>>>,
    pending_out: Arc<Mutex<HashMap<SocketAddr, Vec<Vec<u8>>>>>
}

impl WsNativeSocket {
    fn poke(&self) {
        let _ = self.wakeup.send_to(&[1], self.wakeup_addr);
    }

    fn attach_stream(&self, stream: TcpStream, peer: SocketAddr) -> io::Result<()> {
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let ws = io_error!(accept(stream), "Failed to accept websocket from {}: {}", peer)?;
        self.attach_ws(ws, peer);
        Ok(())
    }

    fn attach_ws<S: Read + Write + Send + 'static>(&self, ws: WebSocket<S>, peer: SocketAddr) {
        let peer = mapped_addr(peer);
        let (tx, rx) = mpsc::channel();
        if let Some(queued) = self.pending_out.lock().unwrap().remove(&peer) {
            for msg in queued {
                let _ = tx.send(msg);
            }
        }
        self.conns.lock().unwrap().insert(peer, tx);
        self.connecting.lock().unwrap().remove(&peer);
        let inbound = self.inbound.clone();
        let wakeup = self.wakeup.try_clone().expect("clone wakeup");
        let wakeup_addr = self.wakeup_addr;
        let conns = self.conns.clone();
        spawn(move || run_ws_conn(ws, peer, inbound, wakeup, wakeup_addr, rx, conns));
        self.poke();
    }

    fn connect_out(&self, addr: SocketAddr, first: Vec<u8>) {
        let addr = mapped_addr(addr);
        {
            let mut connecting = self.connecting.lock().unwrap();
            if self.conns.lock().unwrap().contains_key(&addr) || connecting.contains(&addr) {
                self.pending_out.lock().unwrap().entry(addr).or_default().push(first);
                return;
            }
            connecting.insert(addr);
        }
        self.pending_out.lock().unwrap().entry(addr).or_default().push(first);
        let url = ws_peer_url(addr);
        let inbound = self.inbound.clone();
        let wakeup = self.wakeup.try_clone().expect("clone wakeup");
        let wakeup_addr = self.wakeup_addr;
        let conns = self.conns.clone();
        let connecting = self.connecting.clone();
        let pending_out = self.pending_out.clone();
        spawn(move || {
            match connect(&url) {
                Ok((mut ws, _)) => {
                    let _ = ws.get_mut().set_nodelay(true);
                    if let MaybeTlsStream::Plain(stream) = ws.get_mut() {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    }
                    let (tx, rx) = mpsc::channel();
                    if let Some(queued) = pending_out.lock().unwrap().remove(&addr) {
                        for msg in queued {
                            let _ = tx.send(msg);
                        }
                    }
                    conns.lock().unwrap().insert(addr, tx);
                    connecting.lock().unwrap().remove(&addr);
                    let _ = wakeup.send_to(&[1], wakeup_addr);
                    run_ws_conn(ws, addr, inbound, wakeup, wakeup_addr, rx, conns);
                }
                Err(err) => {
                    warn!("Native websocket connect to {} failed: {}", url, err);
                    connecting.lock().unwrap().remove(&addr);
                    pending_out.lock().unwrap().remove(&addr);
                }
            }
        });
    }
}

#[cfg(unix)]
impl AsRawFd for WsNativeSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.wakeup.as_raw_fd()
    }
}

#[cfg(windows)]
impl AsRawSocket for WsNativeSocket {
    fn as_raw_socket(&self) -> RawSocket {
        self.wakeup.as_raw_socket()
    }
}

#[cfg(windows)]
impl crate::poll::Pollable for WsNativeSocket {
    fn wait_socket(&self) -> Option<std::os::windows::io::RawSocket> {
        Some(self.as_raw_socket())
    }
}

impl Socket for WsNativeSocket {
    fn listen(url: &str) -> Result<Self, io::Error> {
        let bind_str = native_ws_bind(url)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("Not a native websocket listen URL: {}", url)))?;
        let bind_addr = parse_listen(&bind_str, 8080);
        let listener = bind_tcp(bind_addr)?;
        let local = listener.local_addr()?;
        let (wakeup, wakeup_addr) = wakeup_pair()?;
        let inbound = Arc::new(Mutex::new(VecDeque::new()));
        let conns = Arc::new(Mutex::new(HashMap::new()));
        let connecting = Arc::new(Mutex::new(HashSet::new()));
        let pending_out = Arc::new(Mutex::new(HashMap::new()));
        let socket = WsNativeSocket {
            addr: local,
            wakeup,
            wakeup_addr,
            inbound,
            conns,
            connecting,
            pending_out
        };
        let this = socket.clone_handles();
        spawn(move || {
            info!("Listening for websocket peers on ws://{}", local);
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let peer = match stream.peer_addr() {
                            Ok(p) => p,
                            Err(_) => continue
                        };
                        info!("Native websocket client {} connected", peer);
                        if let Err(err) = this.attach_stream(stream, peer) {
                            error!("Failed to accept websocket from {}: {}", peer, err);
                        }
                    }
                    Err(err) => error!("Websocket accept error: {}", err)
                }
            }
        });
        Ok(socket)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        let mut discard = [0u8; 64];
        while self.wakeup.recv_from(&mut discard).is_ok() {}
        let mut inbound = self.inbound.lock().unwrap();
        if let Some((addr, data)) = inbound.pop_front() {
            if !inbound.is_empty() {
                drop(inbound);
                self.poke();
            } else {
                drop(inbound);
            }
            buffer.clear();
            buffer.set_length(data.len());
            buffer.message_mut().copy_from_slice(&data);
            Ok(addr)
        } else {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no websocket payload"))
        }
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        let addr = mapped_addr(addr);
        if let Some(tx) = self.conns.lock().unwrap().get(&addr) {
            tx.send(data.to_vec()).map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            return Ok(data.len());
        }
        self.connect_out(addr, data.to_vec());
        Ok(data.len())
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        let mut addr = self.addr;
        if addr.ip().is_unspecified() {
            addr.set_ip(get_ip());
        }
        Ok(addr)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        None
    }
}

impl WsNativeSocket {
    fn clone_handles(&self) -> Self {
        Self {
            addr: self.addr,
            wakeup: self.wakeup.try_clone().expect("clone wakeup"),
            wakeup_addr: self.wakeup_addr,
            inbound: self.inbound.clone(),
            conns: self.conns.clone(),
            connecting: self.connecting.clone(),
            pending_out: self.pending_out.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_bind_detects_unspecified() {
        assert_eq!(native_ws_bind("ws://0.0.0.0:8080").as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(native_ws_bind("ws://[::]:8080").as_deref(), Some("[::]:8080"));
        assert_eq!(native_ws_bind("ws://*:8080").as_deref(), Some("*:8080"));
        assert_eq!(native_ws_bind("ws-listen://127.0.0.1:9000").as_deref(), Some("127.0.0.1:9000"));
        assert!(native_ws_bind("ws://example.com:3210").is_none());
        assert!(native_ws_bind("3210").is_none());
    }

    #[test]
    fn native_ws_localhost_send_recv() {
        let mut server = WsNativeSocket::listen("ws-listen://127.0.0.1:0").expect("server listen");
        let dest = server.addr;
        let mut client = WsNativeSocket::listen("ws-listen://127.0.0.1:0").expect("client listen");
        client.send(b"hello-ws", dest).expect("send");
        let mut buf = MsgBuffer::new(0);
        let mut got = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(20));
            match server.receive(&mut buf) {
                Ok(_) => {
                    assert_eq!(buf.message(), b"hello-ws");
                    got = true;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("receive: {}", e)
            }
        }
        assert!(got, "server did not receive websocket payload");
    }
}
