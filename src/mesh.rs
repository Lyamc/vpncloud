// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! UDP mesh socket plus optional TCP fallback (length-prefixed datagrams).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Arc, Mutex},
    thread
};

use crate::{
    net::{mapped_addr, send_addr, Socket},
    port_forwarding::PortForwarding,
    util::MsgBuffer
};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

type Inbound = Arc<Mutex<VecDeque<(SocketAddr, Vec<u8>)>>>;
type Peers = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;
type Connecting = Arc<Mutex<HashSet<SocketAddr>>>;

pub struct MeshSocket {
    udp: UdpSocket,
    inbound: Inbound,
    peers: Peers,
    connecting: Connecting,
    wakeup: SocketAddr,
    #[allow(dead_code)]
    tcp: bool
}

impl MeshSocket {
    pub fn open(addr: &str, tcp: bool) -> io::Result<Self> {
        let udp = UdpSocket::listen(addr)?;
        let local = udp.local_addr()?;
        let inbound: Inbound = Arc::new(Mutex::new(VecDeque::new()));
        let peers: Peers = Arc::new(Mutex::new(HashMap::new()));
        let connecting: Connecting = Arc::new(Mutex::new(HashSet::new()));
        if tcp {
            match tcp_bind(local) {
                Ok(listener) => {
                    let inbound2 = inbound.clone();
                    let peers2 = peers.clone();
                    thread::Builder::new().name("vpncloud-tcp-accept".into()).spawn(move || {
                        for stream in listener.incoming().flatten() {
                            if let Ok(peer) = stream.peer_addr() {
                                spawn_tcp(stream, mapped_addr(peer), inbound2.clone(), peers2.clone(), local);
                            }
                        }
                    })?;
                    info!("TCP fallback listening on {}", local);
                }
                Err(e) => warn!("TCP fallback listen failed on {}: {}", local, e)
            }
        }
        Ok(Self { udp, inbound, peers, connecting, wakeup: local, tcp })
    }

    fn take_tcp(&self) -> Option<(SocketAddr, Vec<u8>)> {
        self.inbound.lock().ok()?.pop_front()
    }
}

fn poke_wakeup(wakeup: SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").or_else(|_| UdpSocket::bind("[::1]:0"));
    if let Ok(s) = sock {
        let _ = s.send_to(&[0xff, 0x00], wakeup);
    }
}

fn is_wakeup_poke(buf: &MsgBuffer) -> bool {
    buf.len() == 2 && buf.message() == [0xff, 0x00]
}

fn tcp_bind(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        let _ = sock.set_only_v6(false);
    }
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    sock.set_nonblocking(false)?;
    Ok(sock.into())
}

fn spawn_tcp(stream: TcpStream, peer: SocketAddr, inbound: Inbound, peers: Peers, wakeup: SocketAddr) {
    let _ = stream.set_nodelay(true);
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    if let Ok(mut map) = peers.lock() {
        map.insert(peer, tx);
    }
    let mut writer = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return
    };
    thread::Builder::new()
        .name("vpncloud-tcp-wr".into())
        .spawn(move || {
            while let Ok(buf) = rx.recv() {
                let len = buf.len() as u16;
                if writer.write_all(&len.to_be_bytes()).is_err() || writer.write_all(&buf).is_err() {
                    break;
                }
            }
        })
        .ok();
    thread::Builder::new()
        .name("vpncloud-tcp-rd".into())
        .spawn(move || {
            let mut stream = stream;
            loop {
                let mut hdr = [0u8; 2];
                if stream.read_exact(&mut hdr).is_err() {
                    break;
                }
                let n = u16::from_be_bytes(hdr) as usize;
                if n == 0 || n > 65500 {
                    break;
                }
                let mut body = vec![0u8; n];
                if stream.read_exact(&mut body).is_err() {
                    break;
                }
                if let Ok(mut q) = inbound.lock() {
                    q.push_back((peer, body));
                }
                poke_wakeup(wakeup);
            }
            if let Ok(mut map) = peers.lock() {
                map.remove(&peer);
            }
        })
        .ok();
}

#[cfg(unix)]
impl AsRawFd for MeshSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.udp.as_raw_fd()
    }
}

#[cfg(windows)]
impl AsRawSocket for MeshSocket {
    fn as_raw_socket(&self) -> RawSocket {
        self.udp.as_raw_socket()
    }
}

impl Socket for MeshSocket {
    fn listen(addr: &str) -> Result<Self, io::Error> {
        Self::open(addr, false)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        if let Some((addr, data)) = self.take_tcp() {
            buffer.clear();
            buffer.set_length(data.len());
            buffer.message_mut().copy_from_slice(&data);
            return Ok(addr);
        }
        loop {
            let src = Socket::receive(&mut self.udp, buffer)?;
            if buffer.len() == 2 && buffer.message() == [0xff, 0x00] {
                if let Some((addr, data)) = self.take_tcp() {
                    buffer.clear();
                    buffer.set_length(data.len());
                    buffer.message_mut().copy_from_slice(&data);
                    return Ok(addr);
                }
                continue;
            }
            return Ok(src);
        }
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        let mapped = mapped_addr(addr);
        if let Ok(map) = self.peers.lock() {
            if let Some(tx) = map.get(&mapped).or_else(|| map.get(&addr)).or_else(|| map.get(&send_addr(addr))) {
                let _ = tx.send(data.to_vec());
                return Ok(data.len());
            }
        }
        Socket::send(&mut self.udp, data, addr)
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        Socket::address(&self.udp)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        Socket::create_port_forwarding(&self.udp)
    }

    fn connect_stream(&self, addr: SocketAddr) -> io::Result<()> {
        let mapped = mapped_addr(addr);
        if let Ok(map) = self.peers.lock() {
            if map.contains_key(&mapped) || map.contains_key(&addr) {
                return Ok(());
            }
        }
        if let Ok(mut c) = self.connecting.lock() {
            if !c.insert(mapped) {
                return Ok(());
            }
        }
        let dest = send_addr(addr);
        let inbound = self.inbound.clone();
        let peers = self.peers.clone();
        let connecting = self.connecting.clone();
        let wakeup = self.wakeup;
        thread::Builder::new().name("vpncloud-tcp-connect".into()).spawn(move || {
            match TcpStream::connect(dest) {
                Ok(stream) => {
                    spawn_tcp(stream, mapped, inbound, peers, wakeup);
                    poke_wakeup(wakeup);
                }
                Err(e) => debug!("TCP fallback connect to {} failed: {}", dest, e)
            }
            if let Ok(mut c) = connecting.lock() {
                c.remove(&mapped);
            }
        })?;
        Ok(())
    }

    fn receive_batch(&mut self, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]) -> io::Result<usize> {
        let max = bufs.len().min(addrs.len());
        if max == 0 {
            return Ok(0);
        }
        let mut n = 0;
        while n < max {
            if let Some((addr, data)) = self.take_tcp() {
                bufs[n].clear();
                bufs[n].set_length(data.len());
                bufs[n].message_mut().copy_from_slice(&data);
                addrs[n] = addr;
                n += 1;
                continue;
            }
            break;
        }
        if n >= max {
            return Ok(n);
        }
        match Socket::receive_batch(&mut self.udp, &mut bufs[n..], &mut addrs[n..]) {
            Ok(m) => {
                let start = n;
                let end = n + m;
                let mut w = start;
                for i in start..end {
                    if is_wakeup_poke(&bufs[i]) {
                        continue;
                    }
                    if w != i {
                        addrs[w] = addrs[i];
                        let tmp = bufs[i].message().to_vec();
                        bufs[w].clear();
                        bufs[w].set_length(tmp.len());
                        bufs[w].message_mut().copy_from_slice(&tmp);
                    }
                    w += 1;
                }
                Ok(w)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock && n > 0 => Ok(n),
            Err(_e) if n > 0 => Ok(n),
            Err(e) => Err(e)
        }
    }

    fn send_batch(&mut self, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
        let mut udp: Vec<(&SocketAddr, &[u8])> = Vec::with_capacity(packets.len());
        let mut n = 0;
        for (addr, data) in packets {
            let mapped = mapped_addr(**addr);
            let via_tcp = if let Ok(map) = self.peers.lock() {
                map.get(&mapped).or_else(|| map.get(addr)).or_else(|| map.get(&send_addr(**addr))).cloned()
            } else {
                None
            };
            if let Some(tx) = via_tcp {
                let _ = tx.send(data.to_vec());
                n += 1;
            } else {
                udp.push((*addr, *data));
            }
        }
        if !udp.is_empty() {
            n += Socket::send_batch(&mut self.udp, &udp)?;
        }
        Ok(n)
    }
}

#[cfg(windows)]
impl crate::poll::Pollable for MeshSocket {
    fn wait_socket(&self) -> Option<RawSocket> {
        Some(self.as_raw_socket())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_localhost() {
        let server = MeshSocket::open("127.0.0.1:0", true).expect("listen");
        let addr = server.udp.local_addr().expect("addr");
        let client = MeshSocket::open("127.0.0.1:0", false).expect("client");
        client.connect_stream(addr).expect("connect");
        std::thread::sleep(std::time::Duration::from_millis(150));
        let mut c = client;
        let mut s = server;
        Socket::send(&mut c, b"hello-tcp", addr).expect("send");
        let mut buf = MsgBuffer::new(0);
        for _ in 0..50 {
            match s.receive(&mut buf) {
                Ok(_) if buf.message() == b"hello-tcp" => return,
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("{e}")
            }
        }
        panic!("no tcp frame");
    }
}
