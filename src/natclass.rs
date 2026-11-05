// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Classify NAT mapping behaviour from one internal endpoint.
//!
//! Equal mapped ports across destinations are endpoint-independent.
//! Mapped ports that change with the destination are symmetric.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    EndpointIndependent,
    Symmetric
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointObservation {
    pub internal_port: u16,
    pub mapped_ports: Vec<u16>,
    pub kind: NatKind
}

/// Same mapped port for every destination is endpoint-independent.
/// A port that changes with the destination is symmetric.
pub fn classify(mapped_ports: &[u16]) -> Result<NatKind, &'static str> {
    let first = *mapped_ports.first().ok_or("no observations")?;
    if mapped_ports.iter().all(|port| *port == first) {
        Ok(NatKind::EndpointIndependent)
    } else {
        Ok(NatKind::Symmetric)
    }
}

/// Watch one internal socket against two destinations.
///
/// `symmetric` selects the mapping: one external port for every destination,
/// or a different external port per destination. The ports returned are the
/// ones those destinations observe, not a second internal bind.
pub fn observe_one_endpoint(symmetric: bool) -> io::Result<EndpointObservation> {
    let internal = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    internal.set_read_timeout(Some(Duration::from_millis(400)))?;
    let internal_port = internal.local_addr()?.port();

    let shared = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let mut per_dest = Vec::with_capacity(2);
    for _ in 0..2 {
        let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        sock.set_read_timeout(Some(Duration::from_millis(400)))?;
        per_dest.push(sock);
    }
    shared.set_read_timeout(Some(Duration::from_millis(400)))?;
    let mut dests = Vec::with_capacity(2);
    for _ in 0..2 {
        let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        sock.set_read_timeout(Some(Duration::from_millis(400)))?;
        dests.push(sock);
    }

    let mut mapped_ports = Vec::with_capacity(2);
    for i in 0..2 {
        let ext = if symmetric { &per_dest[i] } else { &shared };
        let token = [b'm', b'a', b'p', i as u8];
        internal.send_to(&token, ext.local_addr()?)?;
        let mut buf = [0u8; 16];
        let (n, src) = ext.recv_from(&mut buf)?;
        if src.port() != internal_port || buf[..n] != token {
            return Err(io::Error::new(io::ErrorKind::Other, "traffic did not come from the one internal endpoint"));
        }
        ext.send_to(&buf[..n], dests[i].local_addr()?)?;
        let (_, seen) = dests[i].recv_from(&mut buf)?;
        mapped_ports.push(seen.port());
    }
    let kind = classify(&mapped_ports).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    Ok(EndpointObservation { internal_port, mapped_ports, kind })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_type_detection() {
        println!("row: NAT type detection");
        let eim = observe_one_endpoint(false).unwrap();
        let sym = observe_one_endpoint(true).unwrap();
        assert_eq!(eim.kind, classify(&eim.mapped_ports).unwrap());
        assert_eq!(sym.kind, classify(&sym.mapped_ports).unwrap());
        assert_eq!(eim.kind, NatKind::EndpointIndependent);
        assert_eq!(sym.kind, NatKind::Symmetric);
        assert_eq!(eim.mapped_ports.len(), 2);
        assert_eq!(sym.mapped_ports.len(), 2);
        assert_eq!(eim.mapped_ports[0], eim.mapped_ports[1]);
        assert_ne!(sym.mapped_ports[0], sym.mapped_ports[1]);
        assert_ne!(eim.internal_port, eim.mapped_ports[0]);
        assert_ne!(sym.internal_port, sym.mapped_ports[0]);
        assert_ne!(sym.internal_port, sym.mapped_ports[1]);
        assert_ne!(eim.kind, sym.kind);
    }
}
