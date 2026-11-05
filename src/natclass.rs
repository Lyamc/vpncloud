// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Classify NAT mapping behaviour from observed external ports.

use std::{
    io,
    net::UdpSocket,
    time::Duration
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    EndpointIndependent,
    Symmetric
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

fn echo_source_port(sock: &UdpSocket) -> io::Result<u16> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_millis(400)))?;
    sock.send_to(b"map", server.local_addr()?)?;
    let mut buf = [0u8; 8];
    let (_, src) = server.recv_from(&mut buf)?;
    Ok(src.port())
}

/// One local socket observed from two destinations.
pub fn observe_endpoint_independent() -> io::Result<NatKind> {
    let client = UdpSocket::bind("127.0.0.1:0")?;
    let first = echo_source_port(&client)?;
    let second = echo_source_port(&client)?;
    classify(&[first, second]).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// A fresh socket per destination, which is the symmetric mapping shape.
pub fn observe_symmetric() -> io::Result<NatKind> {
    let first_sock = UdpSocket::bind("127.0.0.1:0")?;
    let second_sock = UdpSocket::bind("127.0.0.1:0")?;
    let first = echo_source_port(&first_sock)?;
    let second = echo_source_port(&second_sock)?;
    if first == second {
        return Err(io::Error::new(io::ErrorKind::Other, "symmetric observations collided"));
    }
    classify(&[first, second]).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_type_detection() {
        println!("row: NAT type detection");
        let eim = observe_endpoint_independent().unwrap();
        let sym = observe_symmetric().unwrap();
        assert_eq!(eim, NatKind::EndpointIndependent);
        assert_eq!(sym, NatKind::Symmetric);
        assert_ne!(eim, sym);
        assert_eq!(classify(&[9, 9, 9]).unwrap(), NatKind::EndpointIndependent);
        assert_eq!(classify(&[9, 10]).unwrap(), NatKind::Symmetric);
    }
}
