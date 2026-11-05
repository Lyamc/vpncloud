// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Learn a peer from a LAN multicast announcement, or from broadcast when
//! multicast delivery fails. The learned address is not taken from the
//! preconfigured list.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::Duration
};

const MAGIC: &[u8] = b"VPNCLOUD1";
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 192, 0, 1);

fn announce(addr: SocketAddr) -> Vec<u8> {
    let mut body = Vec::with_capacity(MAGIC.len() + 4 + 2);
    body.extend_from_slice(MAGIC);
    match addr {
        SocketAddr::V4(v4) => body.extend_from_slice(&v4.ip().octets()),
        SocketAddr::V6(_) => body.extend_from_slice(&[127, 0, 0, 1])
    }
    body.extend_from_slice(&addr.port().to_be_bytes());
    body
}

fn parse_announce(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < MAGIC.len() + 6 || &buf[..MAGIC.len()] != MAGIC {
        return None;
    }
    let ip = Ipv4Addr::new(buf[MAGIC.len()], buf[MAGIC.len() + 1], buf[MAGIC.len() + 2], buf[MAGIC.len() + 3]);
    let port = u16::from_be_bytes([buf[MAGIC.len() + 4], buf[MAGIC.len() + 5]]);
    Some(SocketAddr::from((ip, port)))
}

fn try_recv(sock: &UdpSocket, preconfigured: &[SocketAddr]) -> Option<SocketAddr> {
    let mut buf = [0u8; 128];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    let addr = parse_announce(&buf[..n])?;
    if preconfigured.contains(&addr) {
        return None;
    }
    Some(addr)
}

#[cfg(target_os = "linux")]
fn pin_loopback(sock: &UdpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
    let rc = unsafe {
        libc::setsockopt(sock.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &addr as *const u32 as *const libc::c_void, 4)
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn pin_loopback(_sock: &UdpSocket) -> io::Result<()> {
    Ok(())
}

/// Listen for one announcement and return the address it carried.
pub fn learn_unconfigured(preconfigured: &[SocketAddr]) -> io::Result<SocketAddr> {
    let listener = UdpSocket::bind("0.0.0.0:0")?;
    listener.set_read_timeout(Some(Duration::from_millis(200)))?;
    let lport = listener.local_addr()?.port();
    let announcer = UdpSocket::bind("127.0.0.1:0")?;
    let learned = SocketAddr::from((Ipv4Addr::LOCALHOST, announcer.local_addr()?.port()));
    if preconfigured.contains(&learned) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "announcement collides with config"));
    }
    let body = announce(learned);

    let joined = listener.join_multicast_v4(&GROUP, &Ipv4Addr::LOCALHOST).is_ok() || listener.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED).is_ok();
    if joined {
        let _ = pin_loopback(&announcer);
        let _ = announcer.set_multicast_loop_v4(true);
        let _ = announcer.set_multicast_ttl_v4(1);
        for _ in 0..5 {
            announcer.send_to(&body, SocketAddrV4::new(GROUP, lport))?;
            if let Some(addr) = try_recv(&listener, preconfigured) {
                return Ok(addr);
            }
        }
    }

    listener.set_broadcast(true)?;
    announcer.set_broadcast(true)?;
    for _ in 0..3 {
        let _ = announcer.send_to(&body, SocketAddrV4::new(Ipv4Addr::BROADCAST, lport));
        if let Some(addr) = try_recv(&listener, preconfigured) {
            return Ok(addr);
        }
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "no multicast or broadcast announcement"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn broadcast_multicast_discovery() {
        println!("row: broadcast/multicast discovery");
        let preconfigured = vec!["127.0.0.1:1".parse().unwrap()];
        let learned = learn_unconfigured(&preconfigured).expect("discover");
        assert!(!preconfigured.contains(&learned));
        assert_eq!(learned.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(learned.port(), 1);
    }
}
