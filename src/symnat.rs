// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Direct exchange across a symmetric mapping.
//!
//! Each peer has one internal socket. A new destination allocates the next
//! pre-bound external port. The peer predicts the other side's next port
//! from that series and sends the raw datagram there.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
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
    pub internal_a: u16,
    pub internal_b: u16,
    pub mapped_a: Vec<u16>,
    pub mapped_b: Vec<u16>,
    pub dest_port: u16,
    pub source_port: u16,
    pub sender_ports: Vec<u16>
}

pub struct Peer {
    internal: UdpSocket,
    external: Vec<UdpSocket>,
    next: usize
}

fn bind_consecutive(count: usize) -> io::Result<Vec<UdpSocket>> {
    let mut base = 20000u16.wrapping_add((std::process::id() as u16).wrapping_mul(32));
    for _ in 0..8000 {
        let mut socks = Vec::with_capacity(count);
        let mut ok = true;
        for offset in 0..count {
            let port = base.wrapping_add(offset as u16);
            match UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) {
                Ok(sock) => {
                    sock.set_read_timeout(Some(Duration::from_millis(400)))?;
                    socks.push(sock);
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && socks.len() == count {
            return Ok(socks);
        }
        base = base.wrapping_add(count as u16);
        if base < 1024 || base > 60000 {
            base = 20000;
        }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "no consecutive port pool"))
}

impl Peer {
    pub fn bind() -> io::Result<Self> {
        let internal = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        internal.set_read_timeout(Some(Duration::from_millis(400)))?;
        Ok(Self { internal, external: bind_consecutive(4)?, next: 0 })
    }

    pub fn internal_port(&self) -> io::Result<u16> {
        Ok(self.internal.local_addr()?.port())
    }

    pub fn bound_ports(&self) -> io::Result<Vec<u16>> {
        let mut ports = vec![self.internal_port()?];
        for sock in &self.external {
            ports.push(sock.local_addr()?.port());
        }
        Ok(ports)
    }

    /// Emit `payload` toward `dest` from the next mapped port of this one internal endpoint.
    fn alloc_send(&mut self, dest: SocketAddr, payload: &[u8]) -> io::Result<u16> {
        if self.next >= self.external.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "mapping pool exhausted"));
        }
        let idx = self.next;
        let ingress = self.external[idx].local_addr()?;
        let internal_port = self.internal_port()?;
        self.internal.send_to(payload, ingress)?;
        let mut buf = vec![0u8; payload.len().max(1)];
        let (n, src) = self.external[idx].recv_from(&mut buf)?;
        if src.port() != internal_port || buf[..n] != *payload {
            return Err(io::Error::new(io::ErrorKind::Other, "send did not originate at the internal endpoint"));
        }
        self.external[idx].send_to(payload, dest)?;
        self.next += 1;
        Ok(ingress.port())
    }

    /// Destination `echo` reports the mapped port it actually saw.
    pub fn probe(&mut self, echo: &UdpSocket) -> io::Result<u16> {
        let sent = self.alloc_send(echo.local_addr()?, b"probe")?;
        let mut buf = [0u8; 16];
        let (n, src) = echo.recv_from(&mut buf)?;
        if &buf[..n] != b"probe" || src.port() != sent {
            return Err(io::Error::new(io::ErrorKind::Other, "probe mapping mismatch"));
        }
        Ok(src.port())
    }

    pub fn send_to_predicted(&mut self, dest: SocketAddr, payload: &[u8]) -> io::Result<u16> {
        self.alloc_send(dest, payload)
    }

    pub fn recv_predicted(&self, port: u16) -> io::Result<(Vec<u8>, SocketAddr)> {
        let sock = self
            .external
            .iter()
            .find(|sock| sock.local_addr().ok().map(|addr| addr.port()) == Some(port))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "predicted port is not mapped on this endpoint"))?;
        let mut buf = [0u8; 2048];
        let (n, from) = sock.recv_from(&mut buf)?;
        Ok((buf[..n].to_vec(), from))
    }
}

/// Next external port implied by a symmetric series. A repeated port is not symmetric.
pub fn predict_next(mapped: &[u16]) -> Result<u16, &'static str> {
    if mapped.len() < 2 {
        return Err("need two mappings");
    }
    let last = *mapped.last().ok_or("need two mappings")? as i32;
    let prev = mapped[mapped.len() - 2] as i32;
    let delta = last - prev;
    if delta == 0 {
        return Err("mapped port did not change per destination");
    }
    let next = last + delta;
    if !(1..=u16::MAX as i32).contains(&next) {
        return Err("predicted port out of range");
    }
    Ok(next as u16)
}

/// Two peers, each one internal socket, exchange `payload` on the port predicted from the other side's mappings.
pub fn predicted_direct(payload: &[u8]) -> io::Result<DirectDatagram> {
    let mut peer_a = Peer::bind()?;
    let mut peer_b = Peer::bind()?;
    let echo1 = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let echo2 = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    echo1.set_read_timeout(Some(Duration::from_millis(400)))?;
    echo2.set_read_timeout(Some(Duration::from_millis(400)))?;

    let internal_a = peer_a.internal_port()?;
    let internal_b = peer_b.internal_port()?;
    let mapped_a = vec![peer_a.probe(&echo1)?, peer_a.probe(&echo2)?];
    let mapped_b = vec![peer_b.probe(&echo1)?, peer_b.probe(&echo2)?];
    if peer_a.internal_port()? != internal_a || peer_b.internal_port()? != internal_b {
        return Err(io::Error::new(io::ErrorKind::Other, "internal identity changed"));
    }
    let dest_port = predict_next(&mapped_b).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let expect_source = predict_next(&mapped_a).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let sender_ports = peer_a.bound_ports()?;
    if sender_ports.contains(&dest_port) {
        return Err(io::Error::new(io::ErrorKind::Other, "predicted port is a socket the sender opened"));
    }
    let dest = SocketAddr::from((Ipv4Addr::LOCALHOST, dest_port));
    let source_port = peer_a.send_to_predicted(dest, payload)?;
    if source_port != expect_source {
        return Err(io::Error::new(io::ErrorKind::Other, "sender mapping left the observed series"));
    }
    let (wire, from) = peer_b.recv_predicted(dest_port)?;
    if from.port() != source_port {
        return Err(io::Error::new(io::ErrorKind::Other, "packet did not arrive from the predicted source"));
    }
    Ok(DirectDatagram {
        payload: wire.clone(),
        path: UnderlayPath::Direct,
        wire,
        internal_a,
        internal_b,
        mapped_a,
        mapped_b,
        dest_port,
        source_port,
        sender_ports
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
        assert_ne!(got.mapped_a[0], got.mapped_a[1]);
        assert_ne!(got.mapped_b[0], got.mapped_b[1]);
        assert_ne!(got.internal_a, got.mapped_a[0]);
        assert_ne!(got.internal_a, got.mapped_a[1]);
        assert_ne!(got.internal_b, got.mapped_b[0]);
        assert_ne!(got.internal_b, got.mapped_b[1]);
        assert_eq!(got.dest_port, predict_next(&got.mapped_b).unwrap());
        assert_eq!(got.source_port, predict_next(&got.mapped_a).unwrap());
        assert!(!got.sender_ports.contains(&got.dest_port));
        let relay = crate::policy::encode_relay(&[0u8; 16], crate::messages::MESSAGE_TYPE_DATA, payload);
        assert_ne!(got.wire, relay);
        assert!(got.wire.len() < 17);
    }
}
