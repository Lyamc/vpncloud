// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, AtomicU64, Ordering}
};

#[cfg(target_os = "linux")]
use std::cell::{Cell, RefCell};

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
    // Prefer the source a routed probe would use. IPv6-only hosts have no
    // route to 8.8.8.8 (#309). A link with no default route still has an
    // address; aborting there took the peer netns down before the tunnel came up.
    if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = s.local_addr() {
                return addr.ip();
            }
        }
    }
    if let Ok(s) = UdpSocket::bind("[::]:0") {
        if s.connect("[2001:4860:4860::8888]:53").is_ok() {
            if let Ok(addr) = s.local_addr() {
                if !addr.ip().is_unspecified() {
                    return addr.ip();
                }
            }
        }
    }
    if let Some(ip) = local_assigned_ip() {
        return ip;
    }
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

/// First non-loopback address on an up interface. IPv4 wins over IPv6.
/// Link-local IPv6 is skipped; it is not a peer address.
fn local_assigned_ip() -> Option<IpAddr> {
    let mut v6 = None;
    let iter = getifaddrs::getifaddrs().ok()?;
    for iface in iter {
        // A MAC entry has no IP. `?` would abandon the rest of the interfaces.
        let Some(ip) = iface.address.ip_addr() else {
            continue;
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        match ip {
            IpAddr::V4(_) => return Some(ip),
            IpAddr::V6(v) if v.is_unicast_link_local() => continue,
            IpAddr::V6(_) if v6.is_none() => v6 = Some(ip),
            IpAddr::V6(_) => {}
        }
    }
    v6
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

    /// UDP descriptor to poll while a short inner train is still arriving.
    ///
    /// Mock and proxy sockets return `None`. Waiting on those descriptors is not a real receive.
    fn gro_wait_fd(&self) -> Option<RawFd> {
        None
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

/// Queue `packets` in order. The `usize` is how many leading packets were
/// accepted, not a byte count. A short count means the caller still owns the rest.
fn default_send_batch<S: Socket>(sock: &mut S, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
    let mut n = 0;
    for (addr, data) in packets {
        match sock.send(data, **addr) {
            Ok(_) => n += 1,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if n > 0 {
                    return Ok(n);
                }
                return Err(e);
            }
            Err(e) => return Err(e)
        }
    }
    Ok(n)
}

fn apply_socket2_buffers(sock: &socket2::Socket, bytes: usize) {
    if bytes == 0 {
        return;
    }
    // `SO_RCVBUF` is clamped to `rmem_max` and then doubled. A 1% deficit at
    // line rate for 30s is tens of megabytes, so ask with the force options
    // when the process can (vpncloud is started with CAP_NET_ADMIN). The
    // kernel still stores twice the value.
    #[cfg(target_os = "linux")]
    if force_socket_buffers(sock.as_raw_fd(), bytes) {
        return;
    }
    let _ = sock.set_recv_buffer_size(bytes);
    let _ = sock.set_send_buffer_size(bytes);
}

/// Set `SO_RCVBUF` / `SO_SNDBUF` on an already-bound UDP socket.
pub fn set_udp_buffer_bytes(sock: &UdpSocket, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let s = socket2::SockRef::from(sock);
    apply_socket2_buffers(&s, bytes);
}

/// `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE` skip `rmem_max`. Returns false when
/// the process lacks `CAP_NET_ADMIN` so the caller can use the clamped options.
#[cfg(target_os = "linux")]
fn force_socket_buffers(fd: RawFd, bytes: usize) -> bool {
    if bytes == 0 || bytes > i32::MAX as usize {
        return false;
    }
    let val = bytes as libc::c_int;
    let recv_ok = unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &val as *const _ as *const libc::c_void, 4) == 0
    };
    let send_ok = unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, &val as *const _ as *const libc::c_void, 4) == 0
    };
    recv_ok && send_ok
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
        // UDP_GRO stays off. Same-size tunnel datagrams merge apart from the
        // shorter ACKs, and splitting that train reordered ACKs and slowed TCP.
        // DF stays on: an oversized send returns EMSGSIZE instead of fragmenting.
        #[cfg(target_os = "linux")]
        {
            dont_fragment(sock.as_raw_fd());
        }
        Ok(sock)
    }

    fn receive(&mut self, buffer: &mut MsgBuffer) -> Result<SocketAddr, io::Error> {
        // One recvmmsg slot, same splitter as the batch path. A GRO train must
        // not surface as a single concatenated payload.
        #[cfg(target_os = "linux")]
        {
            let mut addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
            let n = linux_recvmmsg(self.as_raw_fd(), std::slice::from_mut(buffer), std::slice::from_mut(&mut addr))?;
            if n == 0 {
                return Err(io::Error::new(ErrorKind::WouldBlock, "empty recvmmsg"));
            }
            return Ok(addr);
        }
        #[cfg(not(target_os = "linux"))]
        {
            buffer.clear();
            let (size, addr) = self.recv_from(buffer.buffer())?;
            buffer.set_length(size);
            Ok(addr)
        }
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
        send_batch_fd(self.as_raw_fd(), packets)
    }

    #[cfg(target_os = "linux")]
    fn gro_wait_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }
}

#[cfg(target_os = "linux")]
const UDP_SEGMENT: libc::c_int = 103;
#[cfg(target_os = "linux")]
const UDP_GRO: libc::c_int = 104;

#[cfg(target_os = "linux")]
fn dont_fragment(fd: RawFd) {
    let v4: libc::c_int = libc::IP_PMTUDISC_DO;
    let v6: libc::c_int = libc::IPV6_PMTUDISC_DO;
    unsafe {
        libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, &v4 as *const _ as *const libc::c_void, 4);
        libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, &v6 as *const _ as *const libc::c_void, 4);
    }
}

#[cfg(test)]
fn enable_udp_gro(fd: RawFd) {
    let on: libc::c_int = 1;
    unsafe {
        let _ = libc::setsockopt(fd, libc::IPPROTO_UDP, UDP_GRO, &on as *const _ as *const libc::c_void, 4);
    }
}

/// Path MTU for `dst`, in bytes of IP packet (the interface MTU on a direct link).
///
/// `connect` on a UDP socket does not transmit. It only selects the route so
/// `IP_MTU` / `IPV6_MTU` can be read. Callers that get an error should assume
/// a 1500-byte Ethernet MTU rather than an unbounded one.
#[cfg(target_os = "linux")]
pub fn path_mtu(dst: SocketAddr) -> io::Result<usize> {
    let bind = if dst.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(dst)?;
    let mut mtu: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let (level, opt) =
        if dst.is_ipv4() { (libc::IPPROTO_IP, libc::IP_MTU) } else { (libc::IPPROTO_IPV6, libc::IPV6_MTU) };
    let rc =
        unsafe { libc::getsockopt(sock.as_raw_fd(), level, opt, &mut mtu as *mut _ as *mut libc::c_void, &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if mtu <= 0 {
        return Err(io::Error::new(ErrorKind::InvalidData, "non-positive path mtu"));
    }
    Ok(mtu as usize)
}

#[cfg(not(target_os = "linux"))]
pub fn path_mtu(_dst: SocketAddr) -> io::Result<usize> {
    Err(io::Error::new(ErrorKind::Unsupported, "path mtu probe is only available on linux"))
}

#[cfg(target_os = "linux")]
fn gro_segment_size(hdr: &libc::msghdr) -> usize {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(hdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_UDP && (*cmsg).cmsg_type == UDP_GRO {
                // Older kernels store a u16. Newer ones store the gso size as an int.
                // Little-endian reads of the low half match either layout when the
                // value fits in 16 bits, which every underlay segment does.
                let data = libc::CMSG_DATA(cmsg);
                let cmsg_len = (*cmsg).cmsg_len as usize;
                if cmsg_len >= libc::CMSG_LEN(4) as usize {
                    return u32::from(*(data as *const u32)) as usize;
                }
                if cmsg_len >= libc::CMSG_LEN(2) as usize {
                    return u16::from(*(data as *const u16)) as usize;
                }
                return 0;
            }
            cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
        }
    }
    0
}

/// Split a GRO datagram into segments of `gro` bytes (last may be shorter).
#[cfg(test)]
fn split_gro_payload(payload: &[u8], gro: usize) -> Vec<&[u8]> {
    if gro == 0 || gro >= payload.len() {
        return vec![payload];
    }
    payload.chunks(gro).collect()
}

#[cfg(target_os = "linux")]
struct RecvMmsgScratch {
    names: Vec<libc::sockaddr_storage>,
    iov: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
    cbufs: Vec<[u8; 128]>
}

#[cfg(target_os = "linux")]
struct SendMmsgScratch {
    names: Vec<(libc::sockaddr_storage, u32)>,
    iov: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>
}

#[cfg(target_os = "linux")]
fn linux_msghdr(
    name: *mut libc::c_void, namelen: u32, iov: *mut libc::iovec, control: *mut libc::c_void, controllen: usize
) -> libc::msghdr {
    // musl's msghdr has private padding; zero then fill public fields.
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = name;
    hdr.msg_namelen = namelen;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control;
    hdr.msg_controllen = controllen as _;
    hdr
}

#[cfg(target_os = "linux")]
fn linux_mmsghdr(msg_hdr: libc::msghdr) -> libc::mmsghdr {
    let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
    hdr.msg_hdr = msg_hdr;
    hdr.msg_len = 0;
    hdr
}

#[cfg(target_os = "linux")]
thread_local! {
    static RECV_MMSG: RefCell<RecvMmsgScratch> =
        RefCell::new(RecvMmsgScratch { names: Vec::new(), iov: Vec::new(), hdrs: Vec::new(), cbufs: Vec::new() });
    static SEND_MMSG: RefCell<SendMmsgScratch> =
        RefCell::new(SendMmsgScratch { names: Vec::new(), iov: Vec::new(), hdrs: Vec::new() });
    static GSO_CONCAT: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    // UDP GRO can turn one recvmmsg slot into dozens of segments. Segments that do not
    // fit in this batch are kept per socket and returned on the next receive, in order.
    // A single queue would hand socket A's tail to socket B.
    static GRO_PENDING: RefCell<HashMap<RawFd, VecDeque<(SocketAddr, Vec<u8>)>>> =
        RefCell::new(HashMap::new());
}

/// Run `f` only when this socket already has a spilled GRO tail. An empty map
/// lookup is the common case; inserting a queue here would allocate per read.
#[cfg(target_os = "linux")]
fn flush_gro_pending(fd: RawFd, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]) -> usize {
    GRO_PENDING.with(|cell| {
        let mut map = cell.borrow_mut();
        if !map.get(&fd).is_some_and(|q| !q.is_empty()) {
            map.remove(&fd);
            return 0;
        }
        let n = {
            let pending = map.get_mut(&fd).expect("pending");
            take_segments(bufs, addrs, 0, &[], pending)
        };
        if map.get(&fd).is_some_and(|q| q.is_empty()) {
            map.remove(&fd);
        }
        n
    })
}

#[cfg(target_os = "linux")]
fn store_gro_pending(fd: RawFd, pending: VecDeque<(SocketAddr, Vec<u8>)>) {
    if pending.is_empty() {
        return;
    }
    GRO_PENDING.with(|cell| {
        cell.borrow_mut().insert(fd, pending);
    });
}

/// Split datagrams that carry a UDP_GRO segment size. Older segments in `pending` come first.
/// Returns how many segments were written into `bufs`. The rest stay in `pending`.
#[cfg(target_os = "linux")]
fn take_segments(
    bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr], got: usize, gro_sizes: &[usize],
    pending: &mut VecDeque<(SocketAddr, Vec<u8>)>
) -> usize {
    let cap = bufs.len().min(addrs.len());
    if cap == 0 {
        return 0;
    }
    let mut split = !pending.is_empty();
    if !split {
        for i in 0..got {
            let gro = gro_sizes.get(i).copied().unwrap_or(0);
            if gro > 0 && gro < bufs[i].len() {
                split = true;
                break;
            }
        }
    }
    if !split {
        return got.min(cap);
    }
    // One merged skb is the common case. Keep the first segment in place and
    // copy the rest once. The owned path below is for several skbs in one read.
    if pending.is_empty() && got == 1 {
        let gro = gro_sizes.first().copied().unwrap_or(0);
        let total = bufs[0].len();
        if gro > 0 && gro < total {
            let addr = addrs[0];
            let nsegs = (total + gro - 1) / gro;
            let produce = nsegs.min(cap);
            for s in produce..nsegs {
                let start = s * gro;
                let end = (start + gro).min(total);
                pending.push_back((addr, bufs[0].message()[start..end].to_vec()));
            }
            let src = bufs[0].message().as_ptr();
            for s in (1..produce).rev() {
                let start = s * gro;
                let len = gro.min(total - start);
                bufs[s].clear();
                bufs[s].set_length(len);
                // `src` points at bufs[0]'s allocation, which this write does not touch.
                unsafe {
                    std::ptr::copy_nonoverlapping(src.add(start), bufs[s].message_mut().as_mut_ptr(), len);
                }
                addrs[s] = addr;
            }
            bufs[0].set_length(gro.min(total));
            addrs[0] = addr;
            return produce;
        }
    }
    let mut segs: Vec<(SocketAddr, Vec<u8>)> = Vec::with_capacity(pending.len() + got);
    segs.extend(pending.drain(..));
    for i in 0..got {
        let addr = addrs[i];
        let total = bufs[i].len();
        let gro = gro_sizes.get(i).copied().unwrap_or(0);
        if total == 0 {
            continue;
        }
        if gro == 0 || gro >= total {
            segs.push((addr, bufs[i].message().to_vec()));
            continue;
        }
        for chunk in bufs[i].message().chunks(gro) {
            if !chunk.is_empty() {
                segs.push((addr, chunk.to_vec()));
            }
        }
    }
    let n = segs.len().min(cap);
    for (i, (addr, data)) in segs.iter().take(n).enumerate() {
        addrs[i] = *addr;
        bufs[i].clear();
        bufs[i].clone_from(data);
    }
    for extra in segs.into_iter().skip(n) {
        pending.push_back(extra);
    }
    n
}

#[cfg(target_os = "linux")]
fn linux_recvmmsg(fd: RawFd, bufs: &mut [MsgBuffer], addrs: &mut [SocketAddr]) -> io::Result<usize> {
    let n = bufs.len().min(addrs.len()).min(128);
    if n == 0 {
        return Ok(0);
    }
    // Finish splitting the previous GRO datagram before reading more, so a large
    // coalesce cannot drop segments that do not fit in this batch.
    let flushed = flush_gro_pending(fd, bufs, addrs);
    if flushed > 0 {
        return Ok(flushed);
    }
    RECV_MMSG.with(|cell| {
        let mut s = cell.borrow_mut();
        s.names.resize_with(n, || unsafe { std::mem::zeroed() });
        s.iov.resize(n, libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 });
        s.hdrs.resize_with(n, || unsafe { std::mem::zeroed() });
        if s.cbufs.len() < n {
            s.cbufs.resize(n, [0u8; 128]);
        }
        for i in 0..n {
            bufs[i].clear();
            let buf = bufs[i].buffer();
            s.iov[i] = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
            s.hdrs[i] = linux_mmsghdr(linux_msghdr(
                &mut s.names[i] as *mut _ as *mut _,
                std::mem::size_of::<libc::sockaddr_storage>() as u32,
                &mut s.iov[i],
                s.cbufs[i].as_mut_ptr() as *mut _,
                s.cbufs[i].len()
            ));
        }
        let got =
            unsafe { libc::recvmmsg(fd, s.hdrs.as_mut_ptr(), n as u32, libc::MSG_DONTWAIT as _, std::ptr::null_mut()) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let got = got as usize;
        let mut gro_sizes = [0usize; 128];
        for i in 0..got {
            let mut len = s.hdrs[i].msg_len as usize;
            addrs[i] = sockaddr_to_std(&s.names[i], s.hdrs[i].msg_hdr.msg_namelen)?;
            gro_sizes[i] = gro_segment_size(&s.hdrs[i].msg_hdr);
            // A truncated train is not one ciphertext. Keep only segments that
            // arrived whole; the kernel already discarded the rest.
            if s.hdrs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                let gro = gro_sizes[i];
                if gro > 0 && gro < len {
                    len -= len % gro;
                } else {
                    len = 0;
                }
            }
            bufs[i].set_length(len);
        }
        drop(s);
        let mut pending = VecDeque::new();
        let n = take_segments(bufs, addrs, got, &gro_sizes, &mut pending);
        store_gro_pending(fd, pending);
        Ok(n)
    })
}

/// Ethernet preamble+SFD (8) + header (14) + FCS (4) + interframe gap (12).
const ETH_ON_WIRE: u64 = 38;

/// Bytes a UDP payload occupies on the wire, including the IP header that
/// `send_addr` will actually use. An IPv4-mapped peer is sent as IPv4.
pub(crate) fn datagram_on_wire(addr: SocketAddr, payload_len: usize) -> u64 {
    let ip_hdr = match send_addr(addr) {
        SocketAddr::V4(_) => 20,
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => 20,
        SocketAddr::V6(_) => 40
    };
    payload_len as u64 + ip_hdr + 8 + ETH_ON_WIRE
}

fn packets_on_wire(packets: &[(&SocketAddr, &[u8])]) -> u64 {
    packets.iter().map(|(addr, data)| datagram_on_wire(**addr, data.len())).sum()
}

/// Nanoseconds of line time for `on_wire_bytes` at `bits_per_sec`. Zero when
/// pacing is disabled.
pub(crate) fn airtime_ns(on_wire_bytes: u64, bits_per_sec: u64) -> u64 {
    if bits_per_sec == 0 || on_wire_bytes == 0 {
        return 0;
    }
    on_wire_bytes.saturating_mul(8_000_000_000) / bits_per_sec
}

/// Underlay transmit ceiling in bits per second. `0` means do not pace.
///
/// This is the fallback for when a token bucket cannot be installed on the
/// tunnel. The tunnel qdisc is what blocks the sender: the TUN driver drops
/// a full ring and still returns success, so a sleep here never slows iperf.
static TX_PACE_BPS: AtomicU64 = AtomicU64::new(0);

pub fn set_tx_pace(bits_per_sec: u64) {
    TX_PACE_BPS.store(bits_per_sec, Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
thread_local! {
    static PACE_DEADLINE_NS: Cell<u64> = const { Cell::new(0) };
}

#[cfg(target_os = "linux")]
pub(crate) fn mono_now() -> Option<u64> {
    mono_ns()
}

#[cfg(target_os = "linux")]
fn mono_ns() -> Option<u64> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return None;
    }
    Some((ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64))
}

#[cfg(target_os = "linux")]
fn pace_sleep() {
    if TX_PACE_BPS.load(Ordering::Relaxed) == 0 {
        return;
    }
    let deadline = PACE_DEADLINE_NS.with(|cell| cell.get());
    let Some(now) = mono_ns() else {
        return;
    };
    if deadline <= now {
        return;
    }
    // One call must not stall the process for a huge debt. The deadline stays
    // where it is, so the next chunk sleeps the remainder.
    let target = deadline.min(now.saturating_add(50_000_000));
    let ts = libc::timespec {
        tv_sec: (target / 1_000_000_000) as libc::time_t,
        tv_nsec: (target % 1_000_000_000) as libc::c_long
    };
    while unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &ts, std::ptr::null_mut()) }
        == libc::EINTR
    {}
}

#[cfg(target_os = "linux")]
fn pace_account(on_wire: u64, started: Option<u64>) {
    let bps = TX_PACE_BPS.load(Ordering::Relaxed);
    if bps == 0 || on_wire == 0 {
        return;
    }
    let Some(now) = mono_ns() else {
        return;
    };
    let anchor = started.unwrap_or(now);
    let prev = PACE_DEADLINE_NS.with(|cell| cell.get());
    // An idle gap must not be repaid as a burst.
    let base = if prev > anchor { prev } else { anchor };
    let mut next = base.saturating_add(airtime_ns(on_wire, bps));
    if next < now {
        next = now;
    }
    PACE_DEADLINE_NS.with(|cell| cell.set(next));
}

/// Block until the UDP socket is readable, a requested direction is writable,
/// or `timeout_ms` passes.
///
/// The TUN is not watched for readability. While the UDP socket is full the
/// tunnel stays readable, and waking on it busy-spins without reading.
#[cfg(target_os = "linux")]
pub(crate) fn wait_for_io(
    socket_fd: RawFd, device_fd: RawFd, want_socket_out: bool, want_device_out: bool, timeout_ms: i32
) -> bool {
    let sock_events = libc::POLLIN | if want_socket_out { libc::POLLOUT } else { 0 };
    let mut pfds = [libc::pollfd { fd: socket_fd, events: sock_events, revents: 0 }, libc::pollfd {
        fd: device_fd,
        events: libc::POLLOUT,
        revents: 0
    }];
    let nfds = if want_device_out { 2 } else { 1 };
    loop {
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), nfds, timeout_ms) };
        if rc > 0 {
            return true;
        }
        if rc == 0 {
            return false;
        }
        if io::Error::last_os_error().kind() != ErrorKind::Interrupted {
            return false;
        }
    }
}

/// Block until `fd` is readable, or `timeout_us` passes.
#[cfg(target_os = "linux")]
pub(crate) fn wait_for_read(fd: RawFd, timeout_us: i64) -> bool {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let timeout_us = timeout_us.max(0);
    let ts = libc::timespec {
        tv_sec: (timeout_us / 1_000_000) as libc::time_t,
        tv_nsec: ((timeout_us % 1_000_000) * 1_000) as libc::c_long
    };
    loop {
        let rc = unsafe { libc::ppoll(&mut pfd, 1, &ts, std::ptr::null()) };
        if rc >= 0 {
            return rc > 0;
        }
        if io::Error::last_os_error().kind() != ErrorKind::Interrupted {
            return false;
        }
    }
}

/// Send already-sized datagrams. A same-length run may use UDP_SEGMENT; each
/// segment is still one underlay datagram. Safe to call on `fd` from a thread
/// other than the one blocked in `recvmmsg`.
#[cfg(target_os = "linux")]
pub(crate) fn send_batch_fd(fd: RawFd, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
    linux_sendmmsg(fd, packets)
}

#[cfg(target_os = "linux")]
fn linux_sendmmsg(fd: RawFd, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    // UDP_MAX_SEGMENTS is 64. Send the whole queue in chunks so nothing is dropped.
    // When the tunnel shaper is installed this pace is 0. Otherwise wait out
    // the previous chunk's airtime before offering another. A WouldBlock retry
    // must not reserve that airtime again.
    let mut off = 0;
    while off < packets.len() {
        pace_sleep();
        let started = mono_ns();
        match linux_sendmmsg_chunk(fd, &packets[off..]) {
            Ok(0) => break,
            Ok(n) => {
                let end = off + n;
                // Airtime starts when the chunk is handed to the kernel. Counting
                // from after sendmsg adds the syscall on top of the line time.
                pace_account(packets_on_wire(&packets[off..end]), started);
                off = end;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // The socket is full. Waiting here holds the event loop, so the
                // opposite direction is not read and its TCP window collapses
                // once the link is full. The caller keeps the unsent tail and
                // polls for readability or writability.
                break;
            }
            Err(e) => {
                if off > 0 {
                    return Ok(off);
                }
                return Err(e);
            }
        }
    }
    Ok(off)
}

#[cfg(target_os = "linux")]
fn linux_sendmmsg_chunk(fd: RawFd, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
    let packets = if packets.len() > 64 { &packets[..64] } else { packets };
    // Same destination + same payload size: UDP GSO (one sendmsg, kernel segments).
    // A mixed batch (TCP data plus a short ACK) stays on sendmmsg. Splitting it
    // into short UDP_SEGMENT runs copied every payload and cut goodput.
    if packets.len() > 1 {
        let dest = packets[0].0;
        let seg = packets[0].1.len();
        if seg > 0 && seg <= 65507 && packets.iter().all(|(a, d)| *a == dest && d.len() == seg) {
            if let Ok(n) = linux_gso_send(fd, dest, packets, seg) {
                return Ok(n);
            }
        }
    }
    linux_sendmmsg_plain(fd, packets)
}

#[cfg(target_os = "linux")]
fn linux_sendmmsg_plain(fd: RawFd, packets: &[(&SocketAddr, &[u8])]) -> io::Result<usize> {
    let n = packets.len();
    if n == 0 {
        return Ok(0);
    }
    SEND_MMSG.with(|cell| {
        let mut s = cell.borrow_mut();
        s.names.clear();
        s.iov.clear();
        s.hdrs.clear();
        for (addr, data) in packets.iter().take(n) {
            s.names.push(std_to_sockaddr(**addr));
            s.iov.push(libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() });
        }
        // Index-assign so names/iov and hdrs are distinct field borrows (push() would
        // mutably borrow the whole scratch struct and fail on stable).
        s.hdrs.resize_with(n, || unsafe { std::mem::zeroed() });
        for i in 0..n {
            s.hdrs[i] = linux_mmsghdr(linux_msghdr(
                &mut s.names[i].0 as *mut _ as *mut _,
                s.names[i].1,
                &mut s.iov[i],
                std::ptr::null_mut(),
                0
            ));
        }
        let got = unsafe { libc::sendmmsg(fd, s.hdrs.as_mut_ptr(), n as u32, 0) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(got as usize)
    })
}

#[cfg(target_os = "linux")]
fn linux_gso_send(fd: RawFd, dest: &SocketAddr, packets: &[(&SocketAddr, &[u8])], seg: usize) -> io::Result<usize> {
    GSO_CONCAT.with(|cell| {
        let mut concat = cell.borrow_mut();
        concat.clear();
        let need = seg.saturating_mul(packets.len());
        if concat.capacity() < need {
            concat.reserve(need);
        }
        for (_, d) in packets {
            concat.extend_from_slice(d);
        }
        linux_gso_send_concat(fd, dest, packets.len(), seg, &concat)
    })
}

#[cfg(target_os = "linux")]
fn linux_gso_send_concat(fd: RawFd, dest: &SocketAddr, n: usize, seg: usize, concat: &[u8]) -> io::Result<usize> {
    let mut name = std_to_sockaddr(*dest);
    let mut iov = libc::iovec { iov_base: concat.as_ptr() as *mut _, iov_len: concat.len() };
    let mut cbuf = [0u8; 32];
    let hdr = linux_msghdr(&mut name.0 as *mut _ as *mut _, name.1, &mut iov, cbuf.as_mut_ptr() as *mut _, unsafe {
        libc::CMSG_SPACE(2)
    }
        as usize);
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
    Ok(n)
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

    #[cfg(unix)]
    #[test]
    fn mock_socket_skips_the_gro_hold() {
        let sock = MockSocket::new("127.0.0.1:9".parse().unwrap());
        assert!(sock.gro_wait_fd().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_ip_without_a_default_route_uses_the_interface_address() {
        // The peer netns has only a connected subnet. Connecting to a public
        // resolver fails, and get_ip used to abort the process.
        if std::env::var_os("VPNCLOUD_GETIP_NS").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let out = std::process::Command::new(tool_path("unshare"))
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("net::tests::get_ip_without_a_default_route_uses_the_interface_address")
                .arg("--test-threads=1")
                .env("VPNCLOUD_GETIP_NS", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "get_ip child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(stdout.contains("ok"), "child did not pass: {stdout}\n{stderr}");
            return;
        }
        run_cmd(&tool_path("ip"), &["link", "add", "d0", "type", "dummy"]);
        run_cmd(&tool_path("ip"), &["addr", "add", "192.0.2.9/24", "dev", "d0"]);
        run_cmd(&tool_path("ip"), &["link", "set", "d0", "up"]);
        assert_eq!(get_ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn udp_buffer_request_is_stored_doubled() {
        // The force options need CAP_NET_ADMIN in the initial user namespace,
        // which `sudo` has and a user namespace does not. Either way the
        // stored value is twice what the kernel accepted.
        let sock = UdpSocket::listen("127.0.0.1:0").expect("listen");
        let request = crate::config::DEFAULT_SOCKET_BUFFER;
        set_udp_buffer_bytes(&sock, request);
        let got = socket_opt(&sock, libc::SO_RCVBUF) as usize;
        let send = socket_opt(&sock, libc::SO_SNDBUF) as usize;
        let rmem_max = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .expect("rmem_max")
            .trim()
            .parse::<usize>()
            .expect("rmem_max number");
        let wmem_max = std::fs::read_to_string("/proc/sys/net/core/wmem_max")
            .expect("wmem_max")
            .trim()
            .parse::<usize>()
            .expect("wmem_max number");
        let recv_cap = request.min(rmem_max).saturating_mul(2);
        let send_cap = request.min(wmem_max).saturating_mul(2);
        if got > recv_cap {
            assert_eq!(got, request.saturating_mul(2), "forced rcvbuf");
            assert_eq!(send, request.saturating_mul(2), "forced sndbuf");
        } else {
            assert_eq!(got, recv_cap, "clamped rcvbuf");
            assert_eq!(send, send_cap, "clamped sndbuf");
        }
    }

    #[cfg(target_os = "linux")]
    fn socket_opt(sock: &UdpSocket, opt: libc::c_int) -> libc::c_int {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        val
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_udp_socket_exposes_its_fd_for_the_gro_hold() {
        let sock = UdpSocket::listen("127.0.0.1:0").expect("listen");
        assert_eq!(sock.gro_wait_fd(), Some(sock.as_raw_fd()));
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    fn gro_segments_spill_to_the_next_batch() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut bufs = vec![MsgBuffer::new(0), MsgBuffer::new(0)];
        let mut addrs = vec![addr, addr];
        bufs[0].clone_from(b"aabbccdd");
        let mut pending = VecDeque::new();
        let n = take_segments(&mut bufs, &mut addrs, 1, &[2], &mut pending);
        assert_eq!(n, 2);
        assert_eq!(bufs[0].message(), b"aa");
        assert_eq!(bufs[1].message(), b"bb");
        assert_eq!(pending.len(), 2);
        let n2 = take_segments(&mut bufs, &mut addrs, 0, &[], &mut pending);
        assert_eq!(n2, 2);
        assert_eq!(bufs[0].message(), b"cc");
        assert_eq!(bufs[1].message(), b"dd");
        assert!(pending.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_send_buffer_returns_without_stalling_the_caller() {
        // Loopback orphans a UDP skb before send returns, so the socket never
        // fills. Re-exec inside a user+net namespace whose fq qdisc paces the
        // socket; that is what makes sendmmsg return EAGAIN.
        if std::env::var_os("VPNCLOUD_SEND_FILL").is_none() {
            let exe = std::env::current_exe().expect("current_exe");
            let out = std::process::Command::new(tool_path("unshare"))
                .args(["-Urn", "--"])
                .arg(&exe)
                .arg("--exact")
                .arg("net::tests::full_send_buffer_returns_without_stalling_the_caller")
                .arg("--test-threads=1")
                .env("VPNCLOUD_SEND_FILL", "1")
                .output()
                .expect("spawn unshare");
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "fill child failed: {}\n{stdout}\n{stderr}", out.status);
            assert!(
                stdout.contains("full_send_buffer_returns_without_stalling_the_caller") && stdout.contains("ok"),
                "child did not run the fill: {stdout}\n{stderr}"
            );
            return;
        }
        run_cmd(&tool_path("ip"), &["link", "add", "d0", "type", "dummy"]);
        run_cmd(&tool_path("ip"), &["link", "set", "d0", "up"]);
        run_cmd(&tool_path("ip"), &["addr", "add", "192.0.2.1/24", "dev", "d0"]);
        run_cmd(&tool_path("tc"), &["qdisc", "replace", "dev", "d0", "root", "fq"]);
        let mut client = UdpSocket::listen("192.0.2.1:0").expect("client");
        let fd = client.as_raw_fd();
        let snd: libc::c_int = 16_384;
        let pace: libc::c_uint = 8_000;
        unsafe {
            assert_eq!(
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &snd as *const _ as *const _, 4),
                0,
                "sndbuf: {}",
                io::Error::last_os_error()
            );
            assert_eq!(
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MAX_PACING_RATE, &pace as *const _ as *const _, 4),
                0,
                "pacing: {}",
                io::Error::last_os_error()
            );
        }
        let dst = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 9));
        // Distinct lengths so the batch does not take the UDP_SEGMENT path.
        let payloads: Vec<Vec<u8>> = (0..8).map(|i| vec![7u8; 400 + i * 17]).collect();
        let refs: Vec<(&SocketAddr, &[u8])> = payloads.iter().map(|p| (&dst, p.as_slice())).collect();
        let mut saw_full = false;
        for _ in 0..100 {
            match client.send_batch(&refs) {
                Ok(n) if n < refs.len() => {
                    saw_full = true;
                    break;
                }
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    saw_full = true;
                    break;
                }
                Err(e) => panic!("fill: {e}")
            }
        }
        assert!(saw_full, "send buffer never filled");
        let started = std::time::Instant::now();
        let result = client.send_batch(&refs);
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_millis(5),
            "full socket stalled the sender for {waited:?}: {result:?}"
        );
        match result {
            Ok(n) => assert!(n < refs.len(), "full socket accepted the whole batch ({n})"),
            Err(e) => assert_eq!(e.kind(), ErrorKind::WouldBlock, "{e}")
        }
    }

    #[cfg(target_os = "linux")]
    fn tool_path(name: &str) -> String {
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return candidate.to_string_lossy().into_owned();
                }
            }
        }
        format!("/run/current-system/sw/bin/{name}")
    }

    #[cfg(target_os = "linux")]
    fn run_cmd(bin: &str, args: &[&str]) {
        let out = std::process::Command::new(bin).args(args).output().unwrap_or_else(|e| panic!("{bin}: {e}"));
        assert!(out.status.success(), "{bin} {args:?} -> {}\n{}", out.status, String::from_utf8_lossy(&out.stderr));
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

    #[cfg(target_os = "linux")]
    fn collect_datagrams(sock: &mut UdpSocket, exactly: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = MsgBuffer::new(0);
        let mut spins = 0;
        while out.len() < exactly && spins < 50 {
            match sock.receive(&mut buf) {
                Ok(_) => out.push(buf.message().to_vec()),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    spins += 1;
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(e) => panic!("receive: {e}")
            }
        }
        match sock.receive(&mut buf) {
            Ok(_) => out.push(buf.message().to_vec()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => panic!("receive tail: {e}")
        }
        out
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_length_batch_leaves_as_one_datagram_per_payload() {
        // 1472 is the largest IPv4 UDP payload that fits in one 1500-byte frame.
        // DF is set on the socket. Loopback MTU is 64KB, so a missing UDP_SEGMENT
        // cmsg would deliver one 5888-byte datagram instead of four.
        let mut server = UdpSocket::listen("127.0.0.1:0").expect("server");
        let port = server.local_addr().expect("local").port();
        let mut client = UdpSocket::listen("127.0.0.1:0").expect("client");
        let dst = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
        let payloads: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 1472]).collect();
        let refs: Vec<(&SocketAddr, &[u8])> = payloads.iter().map(|p| (&dst, p.as_slice())).collect();
        let n = client.send_batch(&refs).expect("send");
        assert_eq!(n, refs.len());
        let got = collect_datagrams(&mut server, 4);
        let lens: Vec<usize> = got.iter().map(|g| g.len()).collect();
        assert_eq!(got.len(), 4, "datagrams={lens:?}");
        for (i, g) in got.iter().enumerate() {
            assert_eq!(g.len(), 1472, "datagram {i} len {}", g.len());
            assert!(g.iter().all(|b| *b == i as u8), "datagram {i} payload changed");
        }
    }

    /// More than one `sendmmsg` chunk (the cap is 64) still delivers every datagram.
    #[cfg(target_os = "linux")]
    #[test]
    fn send_batch_above_64_delivers_every_datagram() {
        let mut server = UdpSocket::listen("127.0.0.1:0").expect("server");
        let port = server.local_addr().expect("local").port();
        let mut client = UdpSocket::listen("127.0.0.1:0").expect("client");
        let dst = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
        let n = 65usize;
        let payloads: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; 20 + (i % 5)]).collect();
        let refs: Vec<(&SocketAddr, &[u8])> = payloads.iter().map(|p| (&dst, p.as_slice())).collect();
        let sent = client.send_batch(&refs).expect("send");
        assert_eq!(sent, n);
        let got = collect_datagrams(&mut server, n);
        assert_eq!(got.len(), n, "expected {n} separate datagrams");
        for (i, g) in got.iter().enumerate() {
            assert_eq!(g.len(), 20 + (i % 5));
            assert!(g.iter().all(|b| *b == i as u8));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gro_train_is_one_datagram_per_segment() {
        // 44 * 1472 = 64768. That fits in one UDP datagram (max 65507) and in the
        // 65535-byte buffer after the 100-byte headroom. UDP_GRO may deliver it
        // as one skb. Every segment must come back as its own 1472-byte datagram.
        // DF is set; this must not IP-fragment.
        let mut server = UdpSocket::listen("127.0.0.1:0").expect("server");
        let port = server.local_addr().expect("local").port();
        // listen() leaves GRO off. Turn it on here so this test still exercises the split.
        assert!(!udp_gro_enabled(server.as_raw_fd()), "listen() enabled UDP_GRO");
        enable_udp_gro(server.as_raw_fd());
        assert!(udp_gro_enabled(server.as_raw_fd()), "UDP_GRO was not enabled");
        let mut client = UdpSocket::listen("127.0.0.1:0").expect("client");
        let dst = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
        let nseg = 44usize;
        let payloads: Vec<Vec<u8>> = (0..nseg).map(|i| vec![(i & 0xff) as u8; 1472]).collect();
        let refs: Vec<(&SocketAddr, &[u8])> = payloads.iter().map(|p| (&dst, p.as_slice())).collect();
        let n = client.send_batch(&refs).expect("send");
        assert_eq!(n, nseg);
        let mut bufs = vec![MsgBuffer::new(100); 16];
        let mut addrs = vec![SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)); 16];
        let mut got = Vec::new();
        for _ in 0..40 {
            match server.receive_batch(&mut bufs, &mut addrs) {
                Ok(0) => std::thread::sleep(std::time::Duration::from_millis(2)),
                Ok(k) => {
                    for i in 0..k {
                        got.push(bufs[i].message().to_vec());
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(e) => panic!("receive_batch: {e}")
            }
            if got.len() >= nseg {
                break;
            }
        }
        assert_eq!(got.len(), nseg, "lens={:?}", got.iter().map(|g| g.len()).collect::<Vec<_>>());
        for (i, g) in got.iter().enumerate() {
            assert_eq!(g.len(), 1472, "datagram {i} was merged or truncated");
            assert!(g.iter().all(|b| *b == (i & 0xff) as u8), "datagram {i} payload changed");
        }
    }

    #[cfg(target_os = "linux")]
    fn udp_gro_enabled(fd: RawFd) -> bool {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_UDP,
                UDP_GRO,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len
            )
        };
        rc == 0 && val == 1
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn send_from_another_thread_keeps_one_datagram_per_payload() {
        // The outbox thread calls the same send path while the datapath thread
        // receives. 1472-byte payloads are one IPv4 underlay frame; DF is set.
        let mut server = UdpSocket::listen("127.0.0.1:0").expect("server");
        let port = server.local_addr().expect("local").port();
        let client = UdpSocket::listen("127.0.0.1:0").expect("client");
        let fd = client.as_raw_fd();
        let dst = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
        let payloads: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 1472]).collect();
        let n = std::thread::spawn(move || {
            let refs: Vec<(&SocketAddr, &[u8])> = payloads.iter().map(|p| (&dst, p.as_slice())).collect();
            send_batch_fd(fd, &refs).expect("send")
        })
        .join()
        .expect("join");
        assert_eq!(n, 4);
        let got = collect_datagrams(&mut server, 4);
        assert_eq!(got.len(), 4, "lens={:?}", got.iter().map(|g| g.len()).collect::<Vec<_>>());
        for (i, g) in got.iter().enumerate() {
            assert_eq!(g.len(), 1472);
            assert!(g.iter().all(|b| *b == i as u8), "datagram {i}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mixed_length_batch_keeps_each_datagram_separate() {
        // Full segments, one short ACK-sized payload, then another full run.
        // Each payload must arrive unchanged and in order, not concatenated.
        let mut server_a = UdpSocket::listen("127.0.0.1:0").expect("server a");
        let mut server_b = UdpSocket::listen("127.0.0.1:0").expect("server b");
        let port_a = server_a.local_addr().expect("local a").port();
        let port_b = server_b.local_addr().expect("local b").port();
        let mut client = UdpSocket::listen("127.0.0.1:0").expect("client");
        let dst_a = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port_a));
        let dst_b = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port_b));
        let payloads = [
            vec![1u8; 1472],
            vec![2u8; 1472],
            vec![3u8; 1472],
            vec![4u8; 80],
            vec![5u8; 1472],
            vec![6u8; 1472],
            vec![7u8; 1472],
            vec![8u8; 1472]
        ];
        let dests = [&dst_a, &dst_a, &dst_a, &dst_a, &dst_a, &dst_a, &dst_b, &dst_b];
        let refs: Vec<(&SocketAddr, &[u8])> =
            dests.iter().zip(payloads.iter()).map(|(d, p)| (*d, p.as_slice())).collect();
        let n = client.send_batch(&refs).expect("send");
        assert_eq!(n, refs.len());
        let got_a = collect_datagrams(&mut server_a, 6);
        let got_b = collect_datagrams(&mut server_b, 2);
        assert_eq!(got_a.len(), 6, "a lens={:?}", got_a.iter().map(|g| g.len()).collect::<Vec<_>>());
        assert_eq!(got_b.len(), 2, "b lens={:?}", got_b.iter().map(|g| g.len()).collect::<Vec<_>>());
        for (i, g) in got_a.iter().enumerate() {
            assert_eq!(g.as_slice(), payloads[i].as_slice(), "a datagram {i}");
        }
        for (i, g) in got_b.iter().enumerate() {
            assert_eq!(g.as_slice(), payloads[6 + i].as_slice(), "b datagram {i}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn long_run_inside_a_mixed_batch_stays_one_datagram_each() {
        // A short ACK, twenty full segments, then another short ACK. A long
        // same-length stretch must not arrive as one concatenated payload, and
        // the shorts must stay in order around it. DF stays set.
        let mut server = UdpSocket::listen("127.0.0.1:0").expect("server");
        let port = server.local_addr().expect("local").port();
        let mut client = UdpSocket::listen("127.0.0.1:0").expect("client");
        let dst = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(22);
        payloads.push(vec![0xA1; 80]);
        for i in 0..20u8 {
            payloads.push(vec![i; 1472]);
        }
        payloads.push(vec![0xA2; 64]);
        let refs: Vec<(&SocketAddr, &[u8])> = payloads.iter().map(|p| (&dst, p.as_slice())).collect();
        let n = client.send_batch(&refs).expect("send");
        assert_eq!(n, refs.len());
        let got = collect_datagrams(&mut server, payloads.len());
        assert_eq!(got.len(), payloads.len(), "lens={:?}", got.iter().map(|g| g.len()).collect::<Vec<_>>());
        for (i, g) in got.iter().enumerate() {
            assert_eq!(g.as_slice(), payloads[i].as_slice(), "datagram {i} len {}", g.len());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_mtu_loopback_is_a_real_interface_mtu() {
        let mtu = path_mtu("127.0.0.1:9".parse().unwrap()).expect("ipv4 path mtu");
        assert!(mtu >= 1500, "{mtu}");
        assert!(mtu <= 65535, "{mtu}");
    }

    #[test]
    fn on_wire_bytes_follow_the_address_family() {
        let v4: SocketAddr = "192.168.88.2:3210".parse().unwrap();
        let v6: SocketAddr = "[fd00:88::2]:3210".parse().unwrap();
        let mapped = mapped_addr(v4);
        assert_eq!(datagram_on_wire(v4, 100), 100 + 20 + 8 + 38);
        assert_eq!(datagram_on_wire(mapped, 100), 100 + 20 + 8 + 38);
        assert_eq!(datagram_on_wire(v6, 100), 100 + 40 + 8 + 38);
        let packets = [(v4, &b"abcd"[..]), (v6, &b"abcdef"[..])];
        let refs: Vec<(&SocketAddr, &[u8])> = packets.iter().map(|(a, d)| (a, *d)).collect();
        assert_eq!(packets_on_wire(&refs), datagram_on_wire(v4, 4) + datagram_on_wire(v6, 6));
    }

    #[test]
    fn airtime_is_line_time_and_zero_when_unpaced() {
        assert_eq!(airtime_ns(1538, 1_000_000_000), 1538 * 8);
        assert_eq!(airtime_ns(1538, 0), 0);
        assert_eq!(airtime_ns(0, 1_000_000_000), 0);
        // 64 MTU-sized IPv4 datagrams are well under fq_codel's ~5 ms queue.
        let chunk = datagram_on_wire("192.168.88.2:3210".parse().unwrap(), 1373) * 64;
        let ns = airtime_ns(chunk, 1_000_000_000);
        assert!(ns < 5_000_000, "{ns}");
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

    #[test]
    fn split_gro_payload_chunks() {
        let p = b"aaabbbcc";
        let segs = super::split_gro_payload(p, 3);
        assert_eq!(segs, vec![&b"aaa"[..], &b"bbb"[..], &b"cc"[..]]);
        assert_eq!(super::split_gro_payload(p, 0), vec![&p[..]]);
        assert_eq!(super::split_gro_payload(p, 8), vec![&p[..]]);
    }
}
