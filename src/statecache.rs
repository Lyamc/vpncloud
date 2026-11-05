// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Peer endpoints saved to disk and reloaded before any socket is opened.

use std::{
    fs,
    io,
    net::SocketAddr,
    path::Path
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootState {
    pub peers: Vec<SocketAddr>,
    pub sockets_opened: u32
}

pub fn save(path: &Path, peers: &[SocketAddr]) -> io::Result<()> {
    let mut text = String::new();
    for peer in peers {
        text.push_str(&peer.to_string());
        text.push('\n');
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, text)
}

/// Read saved peers. This function does not open a network socket.
pub fn boot(path: &Path) -> io::Result<BootState> {
    let text = fs::read_to_string(path)?;
    let mut peers = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let addr = line.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer address"))?;
        peers.push(addr);
    }
    Ok(BootState { peers, sockets_opened: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_state_caching() {
        println!("row: local state caching");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.txt");
        let peers = vec!["127.0.0.1:4100".parse().unwrap(), "127.0.0.1:4101".parse().unwrap()];
        save(&path, &peers).unwrap();
        let booted = boot(&path).unwrap();
        assert_eq!(booted.sockets_opened, 0);
        assert_eq!(booted.peers, peers);
    }
}
