// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Linux multi-queue TUN. Each queue is its own file descriptor. A peer
//! id selects the queue that receives that peer's packet.

use std::{
    ffi::CString,
    io::{self, ErrorKind},
    mem,
    os::unix::{fs::PermissionsExt, io::RawFd},
    path::PathBuf,
    process::Command
};

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;
const IFNAMSIZ: usize = 16;

pub struct TunQueue {
    pub fd: RawFd,
    pub name: String
}

impl Drop for TunQueue {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

fn ifr_name(req: &libc::ifreq) -> String {
    unsafe { std::ffi::CStr::from_ptr(req.ifr_name.as_ptr()) }.to_string_lossy().into_owned()
}

fn put_name(req: &mut libc::ifreq, name: &str) {
    let bytes = name.as_bytes();
    let n = bytes.len().min(IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const libc::c_char, req.ifr_name.as_mut_ptr(), n);
    }
}

fn open_one(name: &str) -> io::Result<(RawFd, String)> {
    let path = CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut req: libc::ifreq = unsafe { mem::zeroed() };
    req.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    if !name.is_empty() {
        put_name(&mut req, name);
    }
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut req) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok((fd, ifr_name(&req)))
}

fn bring_up(name: &str) -> io::Result<()> {
    let try_ip = Command::new("ip").args(["link", "set", name, "up"]).status();
    if matches!(&try_ip, Ok(status) if status.success()) {
        return Ok(());
    }
    let status = Command::new("sudo").args(["-n", "ip", "link", "set", name, "up"]).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::Other, "ip link set up failed"))
    }
}

fn open_direct(count: usize) -> io::Result<Vec<TunQueue>> {
    let (fd, name) = open_one("")?;
    bring_up(&name)?;
    let mut queues = vec![TunQueue { fd, name: name.clone() }];
    for _ in 1..count {
        let (fd, got) = open_one(&name)?;
        if got != name {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(ErrorKind::Other, "queue attached to a different device"));
        }
        queues.push(TunQueue { fd, name: got });
    }
    Ok(queues)
}

fn helper_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/vpncloud-tun-helper")
}

fn compile_helper() -> io::Result<PathBuf> {
    let bin = helper_bin();
    if let Some(parent) = bin.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("kernel/tun_helper.c");
    let status = Command::new("clang").args(["-O2", "-o"]).arg(&bin).arg(&src).status()?;
    if !status.success() {
        return Err(io::Error::new(ErrorKind::Other, "tun helper compile failed"));
    }
    Ok(bin)
}

fn recv_tun_fds(fd: RawFd, expect: usize) -> io::Result<(String, Vec<RawFd>)> {
    let mut name = [0u8; IFNAMSIZ];
    let mut iov = libc::iovec { iov_base: name.as_mut_ptr() as *mut libc::c_void, iov_len: name.len() };
    let mut cbuf = vec![0u8; 256];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fds = Vec::new();
    let mut hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !hdr.is_null() {
        let level = unsafe { (*hdr).cmsg_level };
        let kind = unsafe { (*hdr).cmsg_type };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            let data = unsafe { libc::CMSG_DATA(hdr) } as *const RawFd;
            let bytes = unsafe { (*hdr).cmsg_len as usize - libc::CMSG_LEN(0) as usize };
            let count = bytes / mem::size_of::<RawFd>();
            for i in 0..count {
                fds.push(unsafe { *data.add(i) });
            }
        }
        hdr = unsafe { libc::CMSG_NXTHDR(&msg, hdr) };
    }
    if fds.len() != expect {
        for fd in fds {
            unsafe { libc::close(fd) };
        }
        return Err(io::Error::new(ErrorKind::Other, "tun helper returned the wrong fd count"));
    }
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    let text = String::from_utf8_lossy(&name[..end]).into_owned();
    Ok((text, fds))
}

fn open_via_root(count: usize) -> io::Result<Vec<TunQueue>> {
    use std::{
        os::unix::{io::AsRawFd, net::UnixListener},
        time::{Duration, Instant}
    };
    let bin = compile_helper()?;
    let path = std::env::temp_dir().join(format!("vpncloud-tun-{}-{}.sock", std::process::id(), count));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    listener.set_nonblocking(true)?;
    let mut child = Command::new("sudo")
        .args(["-n", bin.to_str().ok_or_else(|| io::Error::new(ErrorKind::Other, "helper path"))?])
        .arg(&path)
        .arg(count.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if let Some(status) = child.try_wait()? {
                    let mut err_text = String::new();
                    if let Some(mut stderr) = child.stderr.take() {
                        use std::io::Read;
                        let _ = stderr.read_to_string(&mut err_text);
                    }
                    let _ = std::fs::remove_file(&path);
                    return Err(io::Error::new(ErrorKind::PermissionDenied, format!("tun helper exited {status}: {err_text}")));
                }
                if start.elapsed() > Duration::from_secs(5) {
                    let _ = child.kill();
                    let _ = std::fs::remove_file(&path);
                    return Err(io::Error::new(ErrorKind::TimedOut, "tun helper"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err)
        }
    };
    let (name, fds) = recv_tun_fds(stream.as_raw_fd(), count)?;
    let _ = child.wait();
    let _ = std::fs::remove_file(&path);
    Ok(fds.into_iter().map(|fd| TunQueue { fd, name: name.clone() }).collect())
}

/// Open `count` queues on one TUN device.
///
/// A direct `TUNSETIFF` is used when this process may create a device.
/// Otherwise a root helper passes already-open queue fds back.
pub fn open_queues(count: usize) -> io::Result<Vec<TunQueue>> {
    if count == 0 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "need a queue"));
    }
    match open_direct(count) {
        Ok(queues) => Ok(queues),
        Err(err) if err.raw_os_error() == Some(libc::EPERM) || err.kind() == ErrorKind::PermissionDenied => open_via_root(count),
        Err(err) => Err(err)
    }
}

pub fn queue_index(peer: &[u8], queues: usize) -> usize {
    let mut hash = 0usize;
    for byte in peer {
        hash = hash.wrapping_mul(167).wrapping_add(*byte as usize);
    }
    if queues == 0 {
        0
    } else {
        hash % queues
    }
}

pub fn steer_write(queues: &[TunQueue], peer: &[u8], packet: &[u8]) -> io::Result<usize> {
    if queues.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "no queues"));
    }
    let index = queue_index(peer, queues.len());
    let n = unsafe { libc::write(queues[index].fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != packet.len() {
        return Err(io::Error::new(ErrorKind::WriteZero, "short tun write"));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet() -> [u8; 20] {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[2] = 0;
        pkt[3] = 20;
        pkt[8] = 64;
        pkt
    }

    #[test]
    fn multi_queue_tun_per_core_sockets() {
        println!("row: multi-queue TUN / per-core sockets");
        let queues = open_queues(2).expect("multi-queue tun");
        assert!(queues.len() > 1);
        assert_ne!(queues[0].fd, queues[1].fd);
        let peer_a = [1u8; 16];
        let mut peer_b = [2u8; 16];
        let mut guard = 0;
        while queue_index(&peer_a, queues.len()) == queue_index(&peer_b, queues.len()) {
            peer_b[0] = peer_b[0].wrapping_add(1);
            guard += 1;
            assert!(guard < 64);
        }
        let pkt = ipv4_packet();
        let qa = steer_write(&queues, &peer_a, &pkt).unwrap();
        let qb = steer_write(&queues, &peer_b, &pkt).unwrap();
        assert_ne!(qa, qb);
    }
}
