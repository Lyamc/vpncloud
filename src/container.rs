// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Forward one packet through a TUN file descriptor the caller already
//! opened. This function does not open `/dev/net/tun`.

use std::{
    io::{self, ErrorKind},
    os::unix::io::RawFd
};

pub fn forward_packet(fd: RawFd, packet: &[u8]) -> io::Result<usize> {
    let n = unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != packet.len() {
        return Err(io::Error::new(ErrorKind::WriteZero, "short tun write"));
    }
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tun_links() -> Vec<String> {
        let mut found = Vec::new();
        let entries = match fs::read_dir("/proc/self/fd") {
            Ok(entries) => entries,
            Err(_) => return found
        };
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                let text = target.to_string_lossy().to_string();
                if text.contains("tun") {
                    found.push(format!("{}:{text}", entry.file_name().to_string_lossy()));
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn container_support() {
        println!("row: container support");
        let before = tun_links();
        let queues = crate::queues::open_queues(1).expect("supplied tun");
        let mid = tun_links();
        assert!(mid.len() > before.len(), "before {before:?} mid {mid:?}");
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[3] = 20;
        pkt[8] = 64;
        let n = forward_packet(queues[0].fd, &pkt).expect("forward");
        assert_eq!(n, pkt.len());
        let after = tun_links();
        assert_eq!(after, mid);
    }
}
