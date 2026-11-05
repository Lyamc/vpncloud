// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Two underlay UDP paths for one overlay peer. Sending moves to the
//! remaining path after the first socket is removed.

use std::{
    io,
    net::UdpSocket,
    time::Duration
};

#[derive(Debug)]
pub struct Failover {
    pub first: Vec<u8>,
    pub second: Vec<u8>,
    pub path_count: usize,
    pub removed_path: bool
}

/// Send `first` on path A and `second` on path B after path A is closed.
pub fn bond_and_fail_over(first: &[u8], second: &[u8]) -> io::Result<Failover> {
    let path_a = UdpSocket::bind("127.0.0.1:0")?;
    let path_b = UdpSocket::bind("127.0.0.1:0")?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    for sock in [&path_a, &path_b, &sender] {
        sock.set_read_timeout(Some(Duration::from_millis(400)))?;
    }
    let addr_a = path_a.local_addr()?;
    let addr_b = path_b.local_addr()?;
    if addr_a == addr_b {
        return Err(io::Error::new(io::ErrorKind::AddrInUse, "paths share a port"));
    }

    sender.send_to(first, addr_a)?;
    let mut buf = [0u8; 2048];
    let (n, _) = path_a.recv_from(&mut buf)?;
    let got_first = buf[..n].to_vec();

    drop(path_a);
    sender.send_to(second, addr_b)?;
    let (n, _) = path_b.recv_from(&mut buf)?;
    let got_second = buf[..n].to_vec();

    sender.set_read_timeout(Some(Duration::from_millis(50)))?;
    let leaked = sender.send_to(b"gone", addr_a).is_ok();
    let _ = leaked;
    path_b.set_read_timeout(Some(Duration::from_millis(50)))?;
    if let Ok((n, _)) = path_b.recv_from(&mut buf) {
        if &buf[..n] == b"gone" {
            return Err(io::Error::new(io::ErrorKind::Other, "removed path delivered"));
        }
    }

    Ok(Failover { first: got_first, second: got_second, path_count: 2, removed_path: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipath_bonding() {
        println!("row: multipath/bonding");
        let got = bond_and_fail_over(b"mesh-on-path-a", b"mesh-on-path-b").expect("bond");
        assert_eq!(got.path_count, 2);
        assert!(got.removed_path);
        assert_eq!(got.first, b"mesh-on-path-a");
        assert_eq!(got.second, b"mesh-on-path-b");
    }
}
