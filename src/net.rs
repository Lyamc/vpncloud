// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, Ordering}
};

#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

#[cfg(unix)] use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

use super::util::{MockTimeSource, MsgBuffer, Time, TimeSource};
use crate::{config::DEFAULT_PORT, port_forwarding::PortForwarding};

pub fn mapped_addr(addr: SocketAddr) -> SocketAddr {
    // HOT PATH
    match addr {
        SocketAddr::V4(addr4) => SocketAddr::new(IpAddr::V6(addr4.ip().to_ipv6_mapped()), addr4.port()),
        _ => addr
    }
}

/// Alternate IPv4 encoding for `send_to` on a dual-stack socket.
///
/// VpnCloud stores IPv4 peers as IPv6-mapped (`::ffff:x.x.x.x`). `send_to` with that form works
/// on an AF_INET6 socket on Linux and macOS; native IPv4 does not on macOS (EINVAL). If a send
/// fails with InvalidInput, retry with the other encoding.
pub fn send_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                addr
            }
        }
        v4 => mapped_addr(v4)
    }
}

pub fn get_ip() -> IpAddr {
    // Prefer IPv4, but IPv6-only hosts have no route to 8.8.8.8 (#309).
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = s.local_addr() {
                return addr.ip();
            }
        }
    }
    let s = UdpSocket::bind("[::]:0").expect("Failed to bind a UDP socket");
    s.connect("[2001:4860:4860::8888]:53").expect("Failed to connect");
    s.local_addr().expect("Failed to get local address").ip()
}

#[cfg(unix)]
pub trait Socket: AsRawFd + Sized {
    fn listen(addr: &str) -> Result<Self, io::Error>;
    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error>;
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error>;
    fn address(&self) -> Result<SocketAddr, io::Error>;
    fn create_port_forwarding(&self) -> Option<PortForwarding>;
    fn connect_stream(&self, _addr: SocketAddr) -> io::Result<()> {
        Ok(())
    }
    fn receive_batch(&mut self, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]) -> io::Result<usize> {
        default_receive_batch(self, bufs, addrs)
    }
    fn send_batch(&mut self, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
        default_send_batch(self, packets)
    }
}

#[cfg(windows)]
pub trait Socket: AsRawSocket + Sized {
    fn listen(addr: &str) -> Result<Self, io::Error>;
    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error>;
    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error>;
    fn address(&self) -> Result<SocketAddr, io::Error>;
    fn create_port_forwarding(&self) -> Option<PortForwarding>;
    fn connect_stream(&self, _addr: SocketAddr) -> io::Result<()> {
        Ok(())
    }
    fn receive_batch(&mut self, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]) -> io::Result<usize> {
        default_receive_batch(self, bufs, addrs)
    }
    fn send_batch(&mut self, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
        default_send_batch(self, packets)
    }
}

fn default_receive_batch<S: Socket>(
    sock: &mut S, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]
) -> io::Result<usize> {
    let max = bufs.len().min(addrs.len());
    if max == 0 {
        return Ok(0);
    }
    match sock.receive(&mut bufs[0]) {
        Ok(a) => {
            addrs[0] = a;
            Ok(1)
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
        Err(e) => Err(e)
    }
}

fn default_send_batch<S: Socket>(sock: &mut S, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
    let mut n = 0;
    for (addr, data) in packets {
        n += sock.send(data, **addr)?;
    }
    Ok(n)
}

fn apply_socket2_buffers(sock: &socket2::Socket, bytes: usize) {
    let _ = sock.set_recv_buffer_size(bytes);
    let _ = sock.set_send_buffer_size(bytes);
}

/// Set `SO_RCVBUF` / `SO_SNDBUF` on an already-bound UDP socket.
pub fn set_udp_buffer_bytes(sock: &UdpSocket, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let s = socket2::SockRef::from(sock);
    let _ = s.set_recv_buffer_size(bytes);
    let _ = s.set_send_buffer_size(bytes);
}

pub fn parse_listen(addr: &str, default_port: u16) -> SocketAddr {
    if let Some(addr) = addr.strip_prefix("*:") {
        let port = try_fail!(addr.parse::<u16>(), "Invalid port: {}");
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else if addr.contains(':') {
        try_fail!(addr.parse::<SocketAddr>(), "Invalid address: {}: {}", addr)
    } else if let Ok(port) = addr.parse::<u16>() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        let ip = try_fail!(addr.parse::<IpAddr>(), "Invalid addr: {}");
        SocketAddr::new(ip, default_port)
    }
}

#[cfg(unix)]
static SOCKET_PROTECT: Mutex<Option<fn(RawFd) -> io::Result<()>>> = Mutex::new(None);

/// Install a hook invoked on every newly bound UDP socket (Android `VpnService.protect`).
#[cfg(unix)]
pub fn set_socket_protect(hook: Option<fn(RawFd) -> io::Result<()>>) {
    *SOCKET_PROTECT.lock().expect("socket protect lock") = hook;
}

#[cfg(unix)]
fn protect_socket(fd: RawFd) -> io::Result<()> {
    if let Some(hook) = *SOCKET_PROTECT.lock().expect("socket protect lock") {
        hook(fd)?;
    }
    Ok(())
}

impl Socket for UdpSocket {
    fn listen(addr: &str) -> Result<Self, io::Error> {
        let addr = mapped_addr(parse_listen(addr, DEFAULT_PORT));
        let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        sock.set_nonblocking(true)?;
        sock.set_reuse_address(true)?;
        apply_socket2_buffers(&sock, crate::config::DEFAULT_SOCKET_BUFFER);
        // macOS defaults IPV6_V6ONLY to true, which would drop IPv4 peers on an `[::]` bind.
        if addr.is_ipv6() {
            sock.set_only_v6(false)?;
        }
        sock.bind(&addr.into())?;
        let sock: UdpSocket = sock.into();
        #[cfg(unix)]
        protect_socket(sock.as_raw_fd())?;
        Ok(sock)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        buffer.clear();
        let (size, addr) = self.recv_from(buffer.buffer())?;
        buffer.set_length(size);
        Ok(addr)
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        match self.send_to(data, addr) {
            Err(e) if e.kind() == ErrorKind::InvalidInput => self.send_to(data, send_addr(addr)),
            other => other
        }
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        let mut addr = self.local_addr()?;
        addr.set_ip(get_ip());
        Ok(addr)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        PortForwarding::new(self.address().unwrap().port())
    }

    #[cfg(target_os = "linux")]
    fn receive_batch(&mut self, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]) -> io::Result<usize> {
        linux_recvmmsg(self.as_raw_fd(), bufs, addrs)
    }

    #[cfg(target_os = "linux")]
    fn send_batch(&mut self, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
        linux_sendmmsg(self.as_raw_fd(), packets)
    }
}

#[cfg(target_os = "linux")]
const UDP_SEGMENT: libc::c_int = 103;

#[cfg(target_os = "linux")]
fn linux_recvmmsg(fd: RawFd, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]) -> io::Result<usize> {
    let n = bufs.len().min(addrs.len()).min(64);
    if n == 0 {
        return Ok(0);
    }
    let mut names = vec![unsafe { std::mem::zeroed::<libc::sockaddr_storage>() }; n];
    let mut iov = Vec::with_capacity(n);
    let mut hdrs = Vec::with_capacity(n);
    for i in 0..n {
        bufs[i].clear();
        let buf = bufs[i].buffer();
        iov.push(libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() });
    }
    for i in 0..n {
        hdrs.push(libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: &mut names[i] as *mut _ as *mut _,
                msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as u32,
                msg_iov: &mut iov[i],
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0
            },
            msg_len: 0
        });
    }
    let got = unsafe { libc::recvmmsg(fd, hdrs.as_mut_ptr(), n as u32, libc::MSG_DONTWAIT, std::ptr::null_mut()) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let got = got as usize;
    for i in 0..got {
        bufs[i].set_length(hdrs[i].msg_len as usize);
        addrs[i] = sockaddr_to_std(&names[i], hdrs[i].msg_hdr.msg_namelen)?;
    }
    Ok(got)
}

#[cfg(target_os = "linux")]
fn linux_sendmmsg(fd: RawFd, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    // Same destination + same payload size: UDP GSO (one sendmsg, kernel segments).
    if packets.len() > 1 {
        let dest = packets[0].0;
        let seg = packets[0].1.len();
        if seg > 0 && seg <= 65507 && packets.iter().all(|(a, d)| *a == dest && d.len() == seg) {
            if let Ok(n) = linux_gso_send(fd, dest, packets, seg) {
                return Ok(n);
            }
        }
    }
    let n = packets.len().min(64);
    let mut names = Vec::with_capacity(n);
    let mut iov = Vec::with_capacity(n);
    let mut hdrs = Vec::with_capacity(n);
    for (addr, data) in packets.iter().take(n) {
        names.push(std_to_sockaddr(**addr));
        iov.push(libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() });
    }
    for i in 0..n {
        hdrs.push(libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: &mut names[i].0 as *mut _ as *mut _,
                msg_namelen: names[i].1,
                msg_iov: &mut iov[i],
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0
            },
            msg_len: 0
        });
    }
    let got = unsafe { libc::sendmmsg(fd, hdrs.as_mut_ptr(), n as u32, 0) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(got as usize)
}

#[cfg(target_os = "linux")]
fn linux_gso_send(fd: RawFd, dest: &SocketAddr, packets: &[(&SocketAddr, &[u8])], seg: usize) -> io::Result<usize> {
    let mut concat = Vec::with_capacity(seg * packets.len());
    for (_, d) in packets {
        concat.extend_from_slice(d);
    }
    let mut name = std_to_sockaddr(*dest);
    let mut iov = libc::iovec { iov_base: concat.as_ptr() as *mut _, iov_len: concat.len() };
    let mut cbuf = [0u8; 32];
    let mut hdr = libc::msghdr {
        msg_name: &mut name.0 as *mut _ as *mut _,
        msg_namelen: name.1,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cbuf.as_mut_ptr() as *mut _,
        msg_controllen: unsafe { libc::CMSG_SPACE(2) } as _,
        msg_flags: 0
    };
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&hdr);
        if cmsg.is_null() {
            return Err(io::Error::from(ErrorKind::Other));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(2) as _;
        std::ptr::write(libc::CMSG_DATA(cmsg) as *mut u16, seg as u16);
        let rc = libc::sendmsg(fd, &hdr, 0);
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(packets.len())
}

#[cfg(target_os = "linux")]
fn sockaddr_to_std(ss: &libc::sockaddr_storage, len: u32) -> io::Result<SocketAddr> {
    let _ = len;
    unsafe {
        match ss.ss_family as i32 {
            libc::AF_INET => {
                let sin = &*(ss as *const _ as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                Ok(SocketAddr::from((ip, u16::from_be(sin.sin_port))))
            }
            libc::AF_INET6 => {
                let sin6 = &*(ss as *const _ as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                Ok(SocketAddr::from((ip, u16::from_be(sin6.sin6_port))))
            }
            _ => Err(io::Error::from(ErrorKind::InvalidInput))
        }
    }
}

#[cfg(target_os = "linux")]
fn std_to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, u32) {
    let addr = send_addr(addr);
    unsafe {
        let mut ss: libc::sockaddr_storage = std::mem::zeroed();
        match addr {
            SocketAddr::V4(v4) => {
                let sin = &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in);
                sin.sin_family = libc::AF_INET as _;
                sin.sin_port = v4.port().to_be();
                sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                (ss, std::mem::size_of::<libc::sockaddr_in>() as u32)
            }
            SocketAddr::V6(v6) => {
                let sin6 = &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6);
                sin6.sin6_family = libc::AF_INET6 as _;
                sin6.sin6_port = v6.port().to_be();
                sin6.sin6_addr.s6_addr = v6.ip().octets();
                (ss, std::mem::size_of::<libc::sockaddr_in6>() as u32)
            }
        }
    }
}

thread_local! {
    static MOCK_SOCKET_NAT: AtomicBool = AtomicBool::new(false);
}

pub struct MockSocket {
    nat: bool,
    nat_peers: HashMap<SocketAddr, Time>,
    address: SocketAddr,
    outbound: VecDeque<(SocketAddr, Vec<u8>)>,
    inbound: VecDeque<(SocketAddr, Vec<u8>)>
}

impl MockSocket {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            nat: Self::get_nat(),
            nat_peers: HashMap::new(),
            address,
            outbound: VecDeque::with_capacity(10),
            inbound: VecDeque::with_capacity(10)
        }
    }

    pub fn set_nat(nat: bool) {
        MOCK_SOCKET_NAT.with(|t| t.store(nat, Ordering::SeqCst))
    }

    pub fn get_nat() -> bool {
        MOCK_SOCKET_NAT.with(|t| t.load(Ordering::SeqCst))
    }

    pub fn put_inbound(&mut self, from: SocketAddr, data: Vec<u8>) -> bool {
        if !self.nat {
            self.inbound.push_back((from, data));
            return true;
        }
        if let Some(timeout) = self.nat_peers.get(&from) {
            if *timeout >= MockTimeSource::now() {
                self.inbound.push_back((from, data));
                return true;
            }
        }
        warn!("Sender {:?} is filtered out by NAT", from);
        false
    }

    pub fn pop_outbound(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        self.outbound.pop_front()
    }
}

#[cfg(unix)]
impl AsRawFd for MockSocket {
    fn as_raw_fd(&self) -> RawFd {
        unimplemented!()
    }
}

#[cfg(windows)]
impl AsRawSocket for MockSocket {
    fn as_raw_socket(&self) -> RawSocket {
        unimplemented!()
    }
}

#[cfg(windows)]
impl crate::poll::Pollable for MockSocket {}

impl Socket for MockSocket {
    fn listen(addr: &str) -> Result<Self, io::Error> {
        Ok(Self::new(mapped_addr(parse_listen(addr, DEFAULT_PORT))))
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        if let Some((addr, data)) = self.inbound.pop_front() {
            buffer.clear();
            buffer.set_length(data.len());
            buffer.message_mut().copy_from_slice(&data);
            Ok(addr)
        } else {
            Err(io::Error::new(ErrorKind::WouldBlock, "nothing in queue"))
        }
    }

    fn send(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, io::Error> {
        self.outbound.push_back((addr, data.into()));
        if self.nat {
            self.nat_peers.insert(addr, MockTimeSource::now() + 300);
        }
        Ok(data.len())
    }

    fn address(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.address)
    }

    fn create_port_forwarding(&self) -> Option<PortForwarding> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::MsgBuffer;

    #[test]
    fn dual_stack_listen_accepts_ipv4() {
        let mut server = UdpSocket::listen("0").expect("listen");
        let port = server.local_addr().expect("local_addr").port();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client bind");
        client.send_to(b"hi", ("127.0.0.1", port)).expect("send");

        let mut buf = MsgBuffer::new(0);
        for _ in 0..50 {
            match server.receive(&mut buf) {
                Ok(_) => {
                    assert_eq!(buf.message(), b"hi");
                    return;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("receive failed: {}", e)
            }
        }
        panic!("did not receive IPv4 datagram on dual-stack socket");
    }

    #[test]
    fn receive_batch_two_datagrams() {
        let mut server = UdpSocket::listen("127.0.0.1:0").expect("listen");
        let port = server.local_addr().expect("local_addr").port();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client bind");
        client.send_to(b"one", ("127.0.0.1", port)).expect("send1");
        client.send_to(b"two", ("127.0.0.1", port)).expect("send2");
        let mut bufs = vec![MsgBuffer::new(0), MsgBuffer::new(0), MsgBuffer::new(0)];
        let mut addrs = vec!["0.0.0.0:0".parse().unwrap(), "0.0.0.0:0".parse().unwrap(), "0.0.0.0:0".parse().unwrap()];
        let mut msgs = Vec::new();
        for _ in 0..50 {
            match server.receive_batch(&mut bufs, &mut addrs) {
                Ok(n) => {
                    for i in 0..n {
                        msgs.push(bufs[i].message().to_vec());
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("receive_batch: {e}")
            }
            if msgs.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(msgs.len() >= 2, "got {msgs:?}");
        assert!(msgs.iter().any(|m| m == b"one"), "{msgs:?}");
        assert!(msgs.iter().any(|m| m == b"two"), "{msgs:?}");
    }

    #[test]
    fn send_addr_unmaps_ipv4_mapped() {
        let v4: SocketAddr = "1.2.3.4:3210".parse().unwrap();
        let mapped = mapped_addr(v4);
        assert_eq!(mapped, "[::ffff:1.2.3.4]:3210".parse().unwrap());
        assert_eq!(send_addr(mapped), v4);
        assert_eq!(send_addr(v4), mapped);
        let v6: SocketAddr = "[2001:db8::1]:3210".parse().unwrap();
        assert_eq!(send_addr(v6), v6);
    }

    #[test]
    fn dual_stack_send_to_ipv4_peer() {
        let mut server = UdpSocket::listen("0").expect("listen");
        let port = server.local_addr().expect("local_addr").port();
        let mut client = UdpSocket::listen("0").expect("client listen");
        let dest = mapped_addr(SocketAddr::from(([127, 0, 0, 1], port)));
        // Dual-stack (AF_INET6) sockets on macOS must send to IPv6-mapped destinations,
        // not native IPv4. send_addr() keeps mapped form for that reason; this send uses
        // the stored mapped address directly to assert the kernel accepts it.
        Socket::send(&mut client, b"mapped", dest).expect("send to ipv6-mapped dest");
        recv_one(&mut server, b"mapped");

        let native = SocketAddr::from(([127, 0, 0, 1], port));
        Socket::send(&mut client, b"native", native).expect("send native ipv4 via fallback");
        recv_one(&mut server, b"native");
    }

    fn recv_one(server: &mut UdpSocket, expect: &[u8]) {
        let mut buf = MsgBuffer::new(0);
        for _ in 0..50 {
            match server.receive(&mut buf) {
                Ok(_) => {
                    assert_eq!(buf.message(), expect);
                    return;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("receive failed: {}", e)
            }
        }
        panic!("did not receive {:?}", std::str::from_utf8(expect));
    }
}
