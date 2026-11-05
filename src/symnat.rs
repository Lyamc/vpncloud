// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Direct exchange across a symmetric mapping. Each new destination uses
//! the next pre-bound port. Peers send to the predicted port and do not
//! wrap the datagram as a relay frame.

use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::Duration
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnderlayPath {
    Direct,
    Relay
}

#[derive(Debug)]
pub struct DirectDatagram {
    pub payload: Vec<u8>,
    pub path: UnderlayPath,
    pub wire: Vec<u8>,
    pub mapped_ports: Vec<u16>
}

fn bind_consecutive(count: usize) -> io::Result<Vec<UdpSocket>> {
    let mut base = 20000u16 + (std::process::id() as u16).wrapping_mul(16);
    for _ in 0..4000 {
        let mut socks = Vec::with_capacity(count);
        let mut ok = true;
        for offset in 0..count {
            let port = base.wrapping_add(offset as u16);
            match UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port))) {
                Ok(sock) => socks.push(sock),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && socks.len() == count {
            for sock in &socks {
                sock.set_read_timeout(Some(Duration::from_millis(400)))?;
            }
            return Ok(socks);
        }
        base = base.wrapping_add(count as u16).max(1024);
        if base > 60000 {
            base = 20000;
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "no consecutive port pool"))
}

/// Two peers whose source port changes per destination exchange `payload`
/// on the predicted next port of each pool.
pub fn predicted_direct(payload: &[u8]) -> io::Result<DirectDatagram> {
    let pool_a = bind_consecutive(4)?;
    let pool_b = bind_consecutive(4)?;
    let dest1 = UdpSocket::bind("127.0.0.1:0")?;
    let dest2 = UdpSocket::bind("127.0.0.1:0")?;
    dest1.set_read_timeout(Some(Duration::from_millis(400)))?;
    dest2.set_read_timeout(Some(Duration::from_millis(400)))?;

    pool_a[0].send_to(b"d1", dest1.local_addr()?)?;
    pool_a[1].send_to(b"d2", dest2.local_addr()?)?;
    let mut buf = [0u8; 64];
    let (_, src1) = dest1.recv_from(&mut buf)?;
    let (_, src2) = dest2.recv_from(&mut buf)?;
    if src1.port() == src2.port() {
        return Err(io::Error::new(io::ErrorKind::Other, "mapped port did not change"));
    }

    // Two mappings are spent. The next predicted ports are pool[2].
    let predicted_a = pool_a[2].local_addr()?;
    let predicted_b = pool_b[2].local_addr()?;
    pool_a[2].send_to(payload, predicted_b)?;
    let (n, from) = pool_b[2].recv_from(&mut buf)?;
    if from != predicted_a {
        return Err(io::Error::new(io::ErrorKind::Other, "packet did not arrive from the predicted port"));
    }
    let wire = buf[..n].to_vec();
    Ok(DirectDatagram {
        payload: wire.clone(),
        path: UnderlayPath::Direct,
        wire,
        mapped_ports: vec![src1.port(), src2.port(), predicted_a.port()]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_nat_handling() {
        println!("row: symmetric NAT handling");
        let payload = b"sym-direct";
        let got = predicted_direct(payload).unwrap();
        assert_eq!(got.path, UnderlayPath::Direct);
        assert_eq!(got.payload, payload);
        assert_eq!(got.wire, payload);
        assert_ne!(got.mapped_ports[0], got.mapped_ports[1]);
        let relay = crate::policy::encode_relay(&[0u8; 16], crate::messages::MESSAGE_TYPE_DATA, payload);
        assert_ne!(got.wire, relay);
        assert!(got.wire.len() < 17);
    }
}
